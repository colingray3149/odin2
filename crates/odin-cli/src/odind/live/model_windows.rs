//! Model-card context windows for fractional session rollover.
/// Known context windows by model card. Fractional rollover admission requires
/// the selected card's window; unrelated cards may have no catalog window.
pub(super) fn selectable_card_windows(
    registry: &[odin_registry::RegistryObject],
    registry_root: &std::path::Path,
) -> Result<std::collections::BTreeMap<String, u64>, String> {
    let catalog = available_context_windows(&registry_root.join(odin_registry::MODELS_AVAILABLE))?;
    let mut windows = std::collections::BTreeMap::new();
    for object in registry {
        let odin_registry::ObjectConfig::Model(card) = &object.config else {
            continue;
        };
        if !card.enabled || !card.seats {
            continue;
        }
        let served = card.served.as_deref().unwrap_or("");
        let tokens = card
            .window
            .as_ref()
            .and_then(|window| window.context_tokens)
            .or_else(|| catalog.get(served).copied().flatten());
        if let Some(tokens) = tokens.filter(|tokens| *tokens > 0) {
            windows.insert(card.id.clone(), tokens);
        }
    }
    for member in odin_hermes::runtime::local_family()? {
        if member.context > 0 {
            windows.insert(
                format!(
                    "{}/{}",
                    odin_domain::huginn::GATEWAY_PROVIDER,
                    member.lane()
                ),
                member.context,
            );
        }
    }
    Ok(windows)
}

/// `contextWindow` of every AVAILABLE entry by `selector`. An entry the
/// provider leaves null maps to `None`; an unreadable catalog refuses the
/// composition by name instead of degrading to card-only facts.
fn available_context_windows(
    path: &std::path::Path,
) -> Result<std::collections::BTreeMap<String, Option<u64>>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("{} is unreadable: {error}", path.display()))?;
    let parsed: serde_json::Value = serde_json::from_str(&text)
        .map_err(|error| format!("{} is not the AVAILABLE catalog: {error}", path.display()))?;
    let Some(entries) = parsed.get("models").and_then(serde_json::Value::as_array) else {
        return Err(format!("{} has no models array", path.display()));
    };
    Ok(entries
        .iter()
        .filter_map(|entry| {
            let selector = entry.get("selector").and_then(serde_json::Value::as_str)?;
            let window = entry
                .get("contextWindow")
                .and_then(serde_json::Value::as_u64);
            Some((selector.to_owned(), window))
        })
        .collect())
}

#[cfg(test)]
#[path = "../tests/card_windows.rs"]
mod tests;
