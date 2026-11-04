//! The effective context window of a selectable card comes from AVAILABLE
//! by `served` selector; a card `[window]` is the override and the sole
//! source where the catalog has none (the official Claude Code client).

use super::selectable_card_windows;

fn card(id: &str, source: &str) -> odin_registry::RegistryObject {
    odin_registry::schema::parse_object_toml(
        odin_registry::RegistryKind::Model,
        id,
        format!("models/{id}/model.toml"),
        source,
    )
    .expect("card parses")
}

fn catalog(root: &std::path::Path, entries: &str) {
    std::fs::write(
        root.join(odin_registry::MODELS_AVAILABLE),
        format!("{{\"version\": 1, \"models\": [{entries}]}}"),
    )
    .expect("AVAILABLE fixture");
}

fn gateway_card(id: &str, served: &str, window: Option<u64>) -> odin_registry::RegistryObject {
    let window = window
        .map(|tokens| format!("\n[window]\ncontext_tokens = {tokens}\n"))
        .unwrap_or_default();
    card(
        id,
        &format!(
            "schema = \"odin.registry.v1\"
kind = \"model\"
enabled = true
description = \"card\"
strengths = \"card\"
id = \"gateway/{id}\"
served = \"{served}\"
route = \"gateway\"
tier = \"everyday\"
seats = true
{window}"
        ),
    )
}

#[test]
fn the_catalog_supplies_the_window_and_a_card_window_overrides_it() {
    let root = tempfile::tempdir().unwrap();
    catalog(
        root.path(),
        "{\"selector\": \"zai/glm-5.3\", \"contextWindow\": 1000000}, \
         {\"selector\": \"xai-oauth/grok-4.7\", \"contextWindow\": 500000}, \
         {\"selector\": \"kimi-code/k3.1-pro\", \"contextWindow\": null}",
    );
    let registry = [
        gateway_card("terra", "zai/glm-5.3", None),
        // A chosen policy narrows the catalog's window for this card.
        gateway_card("grok", "xai-oauth/grok-4.7", Some(200_000)),
        // An unrelated card without a known window stays unavailable for
        // fractional rollover, without blocking other seats.
        gateway_card("kimi-k31", "kimi-code/k3.1-pro", None),
    ];
    let windows = selectable_card_windows(&registry, root.path()).expect("known windows");
    assert!(!windows.contains_key("gateway/kimi-k31"));
    assert_eq!(windows.get("gateway/terra"), Some(&1_000_000));
    assert_eq!(windows.get("gateway/grok"), Some(&200_000));
}
