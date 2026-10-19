//! Canonical bounded item reads. Byte windows never cross UTF-8 boundaries.

use odin_domain::knowledge::KnowledgeItemId;

use super::{contract::malformed, UriError};

pub(super) const DEFAULT_READ_BYTES: usize = 16_384;
pub(super) const MAX_READ_BYTES: usize = 65_536;

pub(super) struct BrainReadTarget {
    pub item: KnowledgeItemId,
    pub offset: u64,
    pub limit: usize,
}

pub(super) fn parse_brain_id(url: &str, id: &str) -> Result<BrainReadTarget, UriError> {
    let mut parts = id.split('/');
    let raw = parts
        .next()
        .ok_or_else(|| malformed(url, "missing knowledge item"))?;
    let item: KnowledgeItemId = raw
        .parse()
        .map_err(|_| malformed(url, "invalid knowledge item identity"))?;
    if item.to_string() != raw {
        return Err(malformed(url, "noncanonical knowledge item identity"));
    }
    let Some(selector) = parts.next() else {
        return Ok(BrainReadTarget {
            item,
            offset: 0,
            limit: DEFAULT_READ_BYTES,
        });
    };
    if selector != "bytes" {
        return Err(malformed(url, "unknown brain item selector"));
    }
    let offset = canonical_number(url, parts.next())?;
    let limit = canonical_number(url, parts.next())?;
    if parts.next().is_some() || limit == 0 || limit > MAX_READ_BYTES as u64 {
        return Err(malformed(
            url,
            "brain byte window must be within 1..=65536 bytes",
        ));
    }
    Ok(BrainReadTarget {
        item,
        offset,
        limit: limit as usize,
    })
}

fn canonical_number(url: &str, value: Option<&str>) -> Result<u64, UriError> {
    let value = value.ok_or_else(|| malformed(url, "incomplete brain byte window"))?;
    let number: u64 = value
        .parse()
        .map_err(|_| malformed(url, "invalid brain byte offset or limit"))?;
    if number.to_string() != value {
        return Err(malformed(url, "noncanonical brain byte offset or limit"));
    }
    Ok(number)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continuation_grammar_rejects_noncanonical_or_unbounded_windows() {
        let item = KnowledgeItemId::new(odin_domain::Digest::hash(b"page")).to_string();
        let valid = parse_brain_id("brain://test", &format!("{item}/bytes/42/65536")).unwrap();
        assert_eq!((valid.offset, valid.limit), (42, MAX_READ_BYTES));
        for suffix in [
            "/bytes/01/100",
            "/bytes/+1/100",
            "/bytes/1/0",
            "/bytes/1/65537",
            "/bytes/1/100/extra",
            "/bytes/1",
            "/other/1/100",
        ] {
            assert!(parse_brain_id("brain://test", &format!("{item}{suffix}")).is_err());
        }
    }
}
