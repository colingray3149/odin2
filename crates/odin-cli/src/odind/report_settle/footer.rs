//! The report footer's run facts.

use serde_json::{json, Value};

/// The report footer's run facts, from the measured stats.
pub(super) fn footer_meta(stats: &Value) -> Value {
    json!({
        "model": meta_text(stats, "servedModel"),
        "wall_time": meta_number(stats, "wallSeconds", "s"),
        "tool_calls": meta_number(stats, "toolCalls", ""),
        "sites": meta_number(stats, "websites", ""),
        "cost": meta_cost(stats),
    })
}

fn field_unavailable(stats: &Value, field: &str) -> bool {
    stats[field].is_null()
        || stats["unavailable"]
            .as_array()
            .is_some_and(|names| names.iter().any(|name| name.as_str() == Some(field)))
}

fn meta_text(stats: &Value, field: &str) -> String {
    if field_unavailable(stats, field) {
        return "unavailable".to_owned();
    }
    stats[field]
        .as_str()
        .filter(|text| !text.is_empty())
        .unwrap_or("unavailable")
        .to_owned()
}

fn meta_number(stats: &Value, field: &str, suffix: &str) -> String {
    if field_unavailable(stats, field) {
        return "unavailable".to_owned();
    }
    match stats[field].as_u64() {
        Some(value) => format!("{value}{suffix}"),
        None => "unavailable".to_owned(),
    }
}

fn meta_cost(stats: &Value) -> String {
    if field_unavailable(stats, "listPriceUsd") {
        return "unavailable".to_owned();
    }
    let Some(price) = stats["listPriceUsd"].as_f64() else {
        return "unavailable".to_owned();
    };
    let dollars = format!("${price:.2} list price");
    if stats["subscriptionIncluded"] == true {
        format!("{dollars} (included, not billed)")
    } else {
        dollars
    }
}
