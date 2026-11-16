//! The settlement record a report run keeps beside its saved render.

use super::*;

pub(super) fn read_state(directory: &Path) -> SettlementState {
    let Some(parsed) = read_record(directory, SETTLEMENT) else {
        return SettlementState::default();
    };
    SettlementState {
        pdf: parsed["pdf"].as_str().unwrap_or_default().to_owned(),
        bytes: parsed["bytes"].as_u64().unwrap_or(0),
        captured_at: parsed["capturedAt"].as_str().unwrap_or_default().to_owned(),
        content: parsed["content"].as_str().unwrap_or_default().to_owned(),
        offered: parsed["offered"].as_u64().unwrap_or(0) as usize,
        confirmed: parsed["confirmed"].as_u64().unwrap_or(0) as usize,
        page_count: parsed["pageCount"].as_u64().unwrap_or(0) as usize,
        dispatched_answer: parsed["dispatchedAnswer"].as_str().map(str::to_owned),
        content_asks: parsed["contentAsks"].as_u64().unwrap_or(0) as u8,
        renders: parsed["renders"].as_u64().unwrap_or(0) as u8,
        resumed_at: parsed["resumedAt"].as_i64().unwrap_or(0),
        resumes: parsed["resumes"].as_u64().unwrap_or(0) as u8,
        resumed_unmet: parsed["resumedUnmet"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        undone: Undone {
            items: strings(&parsed["undone"]["items"]),
            receipts: strings(&parsed["undone"]["receipts"]),
        },
        node: parsed["node"].as_str().unwrap_or_default().to_owned(),
        export_failures: parsed["exportFailures"].as_u64().unwrap_or(0) as u8,
        export_failed_at: parsed["exportFailedAt"].as_i64().unwrap_or(0),
        export_failure: parsed["exportFailure"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        stall: parsed["stall"].as_str().unwrap_or_default().to_owned(),
        stalls: parsed["stalls"].as_u64().unwrap_or(0) as u8,
        stalled_at: parsed["stalledAt"].as_i64().unwrap_or(0),
    }
}

pub(super) fn strings(list: &Value) -> Vec<String> {
    list.as_array()
        .map(|list| {
            list.iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn write_state(directory: &Path, state: &SettlementState) -> Result<(), String> {
    write_record(
        directory,
        SETTLEMENT,
        &json!({
            "pdf": state.pdf,
            "bytes": state.bytes,
            "capturedAt": state.captured_at,
            "content": state.content,
            "offered": state.offered,
            "confirmed": state.confirmed,
            "pageCount": state.page_count,
            "dispatchedAnswer": state.dispatched_answer,
            "contentAsks": state.content_asks,
            "renders": state.renders,
            "resumedAt": state.resumed_at,
            "resumes": state.resumes,
            "resumedUnmet": state.resumed_unmet,
            "undone": {"items": state.undone.items, "receipts": state.undone.receipts},
            "node": state.node,
            "exportFailures": state.export_failures,
            "exportFailedAt": state.export_failed_at,
            "exportFailure": state.export_failure,
            "stall": state.stall,
            "stalls": state.stalls,
            "stalledAt": state.stalled_at,
        }),
    )
}
