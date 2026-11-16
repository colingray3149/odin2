//! A seat's model is declared in the registry: the chosen `provider/model`
//! leads the seat's `models`, and the first entry is what its sessions open
//! with. `seat.model.set` and Huginn's `SeatModelSet` both land here.

use crate::project_authoring::{DaemonProjectRoute, Edit};

fn path(seat: &str) -> String {
    format!("registry/seats/{seat}/seat.toml")
}

/// The seat declaration with `choice` first in its top-level `models`; the
/// other entries keep their order and the rest of the file is untouched. A
/// family member (`gateway/local/<id>`) is declared when its family's
/// `gateway/local/*` is; it leads alone, so members never pile up.
pub(crate) fn models_led_by(text: &str, choice: &str) -> Result<String, String> {
    let parse = |text: &str| -> Result<toml::Table, String> {
        toml::from_str(text).map_err(|error| format!("seat declaration: {error}"))
    };
    let mut expected = parse(text)?;
    let declared = expected
        .get_mut("models")
        .and_then(toml::Value::as_array_mut)
        .ok_or("the seat declares no models list")?;
    let names = declared
        .iter()
        .map(|value| value.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or("the seat's models are not all provider/model strings")?;
    let member = |name: &str| {
        name.rsplit_once('/').is_some_and(|(family, id)| {
            id != "*"
                && names
                    .iter()
                    .any(|declared| *declared == format!("{family}/*"))
        })
    };
    if !names.iter().any(|name| name == choice) && !member(choice) {
        return Err(format!(
            "{choice} is not one of the seat's declared models: {}",
            names.join(", ")
        ));
    }
    let ordered: Vec<&str> = std::iter::once(choice)
        .chain(
            names
                .iter()
                .map(String::as_str)
                .filter(|name| *name != choice && !member(name)),
        )
        .collect();
    *declared = ordered.iter().map(|name| (*name).into()).collect();
    // `models` is a top-level key, so it sits before the first table header;
    // the array runs to its first `]` (entries are plain provider/model ids).
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let start = lines
        .iter()
        .take_while(|line| !line.trim_start().starts_with('['))
        .position(|line| {
            line.trim_start()
                .strip_prefix("models")
                .is_some_and(|rest| rest.trim_start().starts_with('='))
        })
        .ok_or("the seat's models list is not a top-level line")?;
    let end = (start..lines.len())
        .find(|&index| lines[index].contains(']'))
        .ok_or("the seat's models list never closes")?;
    let rendered = ordered
        .iter()
        .map(|name| toml::Value::String((*name).to_owned()).to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let mut rewritten = String::with_capacity(text.len());
    rewritten.extend(lines[..start].iter().copied());
    rewritten.push_str(&format!("models = [{rendered}]\n"));
    rewritten.extend(lines[end + 1..].iter().copied());
    if parse(&rewritten)? != expected {
        return Err("the seat's models list is not a plain array this edit can reorder".to_owned());
    }
    Ok(rewritten)
}

impl DaemonProjectRoute {
    /// Declares `provider/model` as the seat's model and publishes it,
    /// committed `(runtime, <by>)`. Answers what was declared.
    pub(crate) fn declare_seat_model(
        &self,
        seat: &str,
        provider: &str,
        model: &str,
        by: &str,
    ) -> Result<String, String> {
        let choice = format!("{provider}/{model}");
        let message = format!("seat: model '{seat}' {choice} (runtime, {by})");
        let edited = choice.clone();
        let unchanged_choice = choice.clone();
        let seat_path = path(seat);
        let result = self.transact_checked_optional(
            &message,
            Vec::new(),
            vec![Edit::new(path(seat), path(seat), move |text| {
                models_led_by(text, &edited)
            })],
            &[],
            |_| Ok(()),
            move |root| {
                let text = std::fs::read_to_string(root.join(&seat_path))
                    .map_err(|error| format!("could not read {seat_path}: {error}"))?;
                let declaration: toml::Table =
                    toml::from_str(&text).map_err(|error| format!("seat declaration: {error}"))?;
                Ok(declaration
                    .get("models")
                    .and_then(toml::Value::as_array)
                    .and_then(|models| models.first())
                    .and_then(toml::Value::as_str)
                    == Some(unchanged_choice.as_str()))
            },
        )?;
        match result {
            None => Ok(format!("{choice} is already {seat}'s declared model")),
            Some((revision, commit)) => {
                tracing::info!(
                    "seat model seat={seat} model={choice} revision={revision} commit={commit}"
                );
                Ok(format!(
                    "{seat} is declared on {choice} (registry revision {revision}, commit {})",
                    commit.get(..10).unwrap_or(&commit)
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::models_led_by;

    const SEAT: &str = "schema = \"odin.registry.v1\"\nkind = \"seat\"\n# Launch choices; the first is the default.\nmodels = [\"gateway/grok\", \"gateway/astra\", \"gateway/zai-glm\"]\n\n[context]\nreview_lane = \"grok\"\n";

    #[test]
    fn the_choice_leads_and_the_rest_keep_their_order() {
        let edited = models_led_by(SEAT, "gateway/zai-glm").unwrap();
        assert_eq!(
            edited,
            SEAT.replace(
                "[\"gateway/grok\", \"gateway/astra\", \"gateway/zai-glm\"]",
                "[\"gateway/zai-glm\", \"gateway/grok\", \"gateway/astra\"]"
            )
        );
    }

    #[test]
    fn an_undeclared_model_is_refused_by_name() {
        let error = models_led_by(SEAT, "gateway/kimi-k31").unwrap_err();
        assert!(error.contains("gateway/kimi-k31 is not one of"), "{error}");
    }
}
