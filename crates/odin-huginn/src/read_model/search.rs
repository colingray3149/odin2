/// `needle` is already trimmed and lowercased. Title, summary, and id are
/// folded here so a scan pays that cost once per object, not once per query
/// field plus the needle.
pub(crate) fn relevance_micros(
    needle: &str,
    title: &str,
    summary: &str,
    object_id: &str,
) -> Option<u32> {
    if needle.is_empty() {
        return Some(1);
    }
    let title = title.to_lowercase();
    let summary = summary.to_lowercase();
    let object_id = object_id.to_lowercase();
    let mut score = 0_u32;
    if title == needle {
        score = score.saturating_add(700_000);
    } else if title.starts_with(needle) {
        score = score.saturating_add(500_000);
    } else if title.contains(needle) {
        score = score.saturating_add(350_000);
    }
    if object_id == needle {
        score = score.saturating_add(250_000);
    } else if object_id.contains(needle) {
        score = score.saturating_add(150_000);
    }
    if summary.contains(needle) {
        score = score.saturating_add(100_000);
    }
    (score != 0).then_some(score.min(1_000_000))
}
