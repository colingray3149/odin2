/// Parse the allocation row, not its batch/step rows, into a cumulative running interval.
pub(super) fn parse_slurm_elapsed(row: &str) -> Option<(u64, u64)> {
    let mut fields = row.trim().split('|');
    let start = fields.next()?;
    let seconds: u64 = fields.next()?.parse().ok()?;
    if fields.any(|field| !field.is_empty()) {
        return None;
    }
    if start == "Unknown" && seconds == 0 {
        return Some((0, 0));
    }
    let start_ms = start.parse::<u64>().ok()?.checked_mul(1_000)?;
    let end_ms = start_ms.checked_add(seconds.checked_mul(1_000)?)?;
    Some((start_ms, end_ms))
}

/// Slurm duration format is [days-]hours:minutes:seconds.
pub(super) fn parse_slurm_duration(text: &str) -> Option<u64> {
    let (days, clock) = match text.split_once('-') {
        Some((days, clock)) => (days.parse::<u64>().ok()?, clock),
        None => (0, text),
    };
    let mut fields = clock.split(':');
    let hours: u64 = fields.next()?.parse().ok()?;
    let minutes: u64 = fields.next()?.parse().ok()?;
    let seconds: u64 = fields.next()?.parse().ok()?;
    if fields.next().is_some() || minutes >= 60 || seconds >= 60 {
        return None;
    }
    days.checked_mul(24)?
        .checked_add(hours)?
        .checked_mul(60)?
        .checked_add(minutes)?
        .checked_mul(60)?
        .checked_add(seconds)
}

/// Each `sacct --duplicates` allocation has its own SLUID across requeues.
pub(super) fn parse_slurm_allocations(
    text: &str,
    submitted: i64,
) -> Option<Vec<(String, u64, u64)>> {
    let mut allocations = Vec::new();
    for row in text.split(';').filter(|row| !row.trim().is_empty()) {
        let mut fields = row.trim().split('|');
        let id = fields.next()?;
        if id.is_empty()
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return None;
        }
        let submit: i64 = fields.next()?.parse().ok()?;
        let start = fields.next()?;
        let elapsed = fields.next()?;
        let suspended = fields.next()?;
        if fields.any(|field| !field.is_empty()) {
            return None;
        }
        let (start, end) = parse_slurm_elapsed(&format!("{start}|{elapsed}|"))?;
        let suspended = parse_slurm_duration(suspended)?.checked_mul(1_000)?;
        let active = end.checked_sub(start)?.checked_sub(suspended)?;
        if submit >= submitted {
            allocations.push((id.to_owned(), start, active));
        }
    }
    (!allocations.is_empty()).then_some(allocations)
}
