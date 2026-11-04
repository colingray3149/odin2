//! The owner's conversation commands: `/clear` starts a fresh session from the
//! seat core, and `/model <words>` switches the seat to its closest declared
//! model card, then starts fresh the same way. Discord's client takes a
//! leading `/` for its own commands, so `.clear` and `.model` work too.

use odin_domain::huginn::{ModelName, ProviderName};
use odin_domain::{CommandId, SeatId};
use odin_registry::schema::ObjectConfig;

use super::{HermesRuntime, OwnerDecisionRoute};

pub(super) enum OwnerCommand {
    Clear,
    Model(String),
}

impl OwnerCommand {
    pub(super) fn parse(content: &str) -> Option<Self> {
        let content = content.trim();
        let (word, rest) = content
            .split_once(char::is_whitespace)
            .unwrap_or((content, ""));
        let word = word.to_ascii_lowercase();
        let name = word.strip_prefix('/').or_else(|| word.strip_prefix('.'))?;
        match name {
            "clear" if rest.trim().is_empty() => Some(Self::Clear),
            "model" => Some(Self::Model(rest.trim().to_owned())),
            _ => None,
        }
    }
}

/// One declared launch of the seat with its card's words.
struct Choice {
    provider: ProviderName,
    model: ModelName,
    served: String,
    description: String,
}

fn normalized(text: &str) -> String {
    text.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// The closest choice to `words`; ties keep the seat's declared order.
fn closest<'a>(words: &str, choices: &'a [Choice]) -> Option<&'a Choice> {
    let query = normalized(words);
    if query.is_empty() {
        return None;
    }
    let score = |choice: &Choice| {
        let lane = normalized(choice.model.as_str());
        let served = normalized(&choice.served);
        let description = normalized(&choice.description);
        if query == lane {
            1000
        } else if served.ends_with(&query) {
            900
        } else if query.contains(&lane) {
            500 + lane.len()
        } else if lane.contains(&query) {
            400
        } else if served.contains(&query) {
            300
        } else if description.contains(&query) {
            200
        } else {
            100 * words
                .split_whitespace()
                .map(normalized)
                .filter(|word| {
                    word.len() > 1 && (served.contains(word) || description.contains(word))
                })
                .count()
        }
    };
    let mut best: Option<(usize, &Choice)> = None;
    for choice in choices {
        let points = score(choice);
        if points > 0 && best.is_none_or(|(top, _)| points > top) {
            best = Some((points, choice));
        }
    }
    best.map(|(_, choice)| choice)
}

impl HermesRuntime {
    fn model_choices(&self, seat: &SeatId) -> Vec<Choice> {
        let cards: Vec<_> = self
            .registry_pin()
            .map(|pin| {
                pin.current()
                    .objects
                    .iter()
                    .filter_map(|object| match &object.config {
                        ObjectConfig::Model(card) => Some((
                            card.lane().map(str::to_owned),
                            card.served.clone().unwrap_or_default(),
                            card.description.clone(),
                        )),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let Some(launches) = self.model_launches() else {
            return Vec::new();
        };
        let Some((_, options)) = launches.iter().find(|(declared, _)| *declared == seat) else {
            return Vec::new();
        };
        options
            .iter()
            .map(|(provider, model)| {
                let card = cards
                    .iter()
                    .find(|(lane, _, _)| lane.as_deref() == Some(model.as_str()));
                Choice {
                    provider: provider.clone(),
                    model: model.clone(),
                    served: card
                        .map(|(_, served, _)| served.clone())
                        .unwrap_or_default(),
                    description: card
                        .map(|(_, _, description)| description.clone())
                        .unwrap_or_default(),
                }
            })
            .collect()
    }

    /// Runs one owner command and returns the reply line.
    pub(super) fn run_owner_command(
        &self,
        command: OwnerCommand,
        route: &dyn OwnerDecisionRoute,
        seat: &SeatId,
        command_id: CommandId,
    ) -> String {
        let clear = || {
            super::recovery::bridge_route(route.clear())
                .map_err(|error| error.to_string())
                .and_then(|cleared| cleared)
        };
        match command {
            OwnerCommand::Clear => match clear() {
                Ok(()) => "Cleared. Fresh start.".to_owned(),
                Err(error) => format!("Could not clear: {error}"),
            },
            OwnerCommand::Model(words) => {
                let choices = self.model_choices(seat);
                let Some(choice) = closest(&words, &choices) else {
                    let options = choices
                        .iter()
                        .map(|choice| {
                            format!(
                                "{} ({})",
                                choice.model,
                                choice.description.trim_end_matches('.')
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("; ");
                    return if words.is_empty() {
                        format!("Models: {options}")
                    } else {
                        format!("No model matches \"{words}\". Models: {options}")
                    };
                };
                // Declare first: the fresh session opens on the new model, so
                // a dead current model cannot block the switch away from it.
                if let Err(error) = self.declare_seat_model(
                    command_id,
                    seat.as_str(),
                    choice.provider.as_str(),
                    choice.model.as_str(),
                    "by the owner from the conversation",
                ) {
                    return format!("The switch to {} failed: {error}", choice.model);
                }
                let now = format!(
                    "Now on {} ({})",
                    choice.model,
                    choice.description.trim_end_matches('.')
                );
                match clear() {
                    Ok(()) => format!("{now}. Fresh start."),
                    Err(error) => format!("{now}, but the clear failed: {error}"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{closest, Choice};
    use odin_domain::huginn::{ModelName, ProviderName};

    fn choice(model: &str, served: &str, description: &str) -> Choice {
        Choice {
            provider: ProviderName::new("gateway").unwrap(),
            model: ModelName::new(model).unwrap(),
            served: served.to_owned(),
            description: description.to_owned(),
        }
    }

    #[test]
    fn spoken_names_pick_the_closest_declared_card() {
        let choices = [
            choice("terra", "openai-codex/gpt-6.1-terra", "GPT-6.1 Terra"),
            choice("goat-flash", "commandcode/goat-flash", "GOAT Flash"),
            choice("grok", "xai-oauth/grok-4.7", "Grok 4.7 on SuperGrok"),
            choice("zai-glm", "zai/glm-5.3", "GLM 5.3"),
            choice("glm-flash", "zai/glm-5.3-flash", "GLM 5.3 Flash"),
        ];
        let pick = |words: &str| closest(words, &choices).map(|choice| choice.model.to_string());
        assert_eq!(pick("grok4.7").as_deref(), Some("grok"));
        assert_eq!(pick("Grok 4.7").as_deref(), Some("grok"));
        assert_eq!(pick("terra").as_deref(), Some("terra"));
        assert_eq!(pick("gpt").as_deref(), Some("terra"));
        assert_eq!(pick("glm flash").as_deref(), Some("glm-flash"));
        assert_eq!(pick("glm").as_deref(), Some("zai-glm"));
        assert_eq!(pick("opus"), None);
    }
}
