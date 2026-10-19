//! Projects a bounded contiguous byte window from canonical indexed chunks.

use odin_domain::knowledge::IndexedChunk;
use serde_json::{json, Value};

use super::{brain_ids::BrainReadTarget, contract::malformed, UriError};

pub(super) fn page(
    url: &str,
    target: &BrainReadTarget,
    chunks: &[IndexedChunk],
) -> Result<Value, UriError> {
    let total = chunks
        .iter()
        .map(|chunk| chunk.citation.byte_end)
        .max()
        .unwrap_or(0);
    if target.offset >= total {
        return Err(malformed(url, "brain byte offset is outside the item"));
    }
    let wanted_end = target.offset.saturating_add(target.limit as u64).min(total);
    let mut ordered: Vec<_> = chunks.iter().collect();
    ordered.sort_by_key(|chunk| chunk.citation.byte_start);
    let mut cursor = target.offset;
    let mut text = String::with_capacity(target.limit.min((total - target.offset) as usize));
    for chunk in ordered {
        let start = chunk.citation.byte_start;
        let end = chunk.citation.byte_end;
        if end <= cursor {
            continue;
        }
        if start > cursor {
            return Err(malformed(
                url,
                "knowledge item has a gap in its indexed byte spans",
            ));
        }
        if end.saturating_sub(start) != chunk.text.len() as u64 {
            return Err(malformed(
                url,
                "knowledge chunk text disagrees with its citation span",
            ));
        }
        let from = (cursor - start) as usize;
        if !chunk.text.is_char_boundary(from) {
            return Err(malformed(url, "brain byte offset is not a UTF-8 boundary"));
        }
        let mut to = (wanted_end.min(end) - start) as usize;
        while !chunk.text.is_char_boundary(to) {
            to -= 1;
        }
        text.push_str(&chunk.text[from..to]);
        cursor = start + to as u64;
        if cursor == wanted_end || to < (wanted_end.min(end) - start) as usize {
            break;
        }
    }
    if cursor == target.offset {
        return Err(malformed(
            url,
            "brain byte window cannot fit the next UTF-8 character",
        ));
    }
    let next = (cursor < total)
        .then(|| format!("brain://{}/bytes/{cursor}/{}", target.item, target.limit));
    Ok(
        json!({"text":text,"byteStart":target.offset,"byteEnd":cursor,"totalBytes":total,"continuation":next}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_domain::{
        knowledge::{AtlasId, Citation, KnowledgeChunkId, KnowledgeItemId, TrustClass},
        Digest,
    };

    #[test]
    fn pages_preserve_utf8_bytes_and_remove_chunk_overlap() {
        let item = KnowledgeItemId::new(Digest::hash(b"item"));
        let make = |start, end, text: &str| IndexedChunk {
            item_id: item,
            chunk_id: KnowledgeChunkId::new(Digest::hash(text.as_bytes())),
            trust: TrustClass::Observed,
            text: text.into(),
            digest: Digest::hash(text.as_bytes()),
            citation: Citation::new(
                AtlasId::new("memory.sinmara").unwrap(),
                Digest::hash(b"head"),
                item,
                None,
                None,
                None,
                None,
                start,
                end,
            )
            .unwrap(),
        };
        let chunks = [make(0, 5, "aébc"), make(3, 8, "bcdef")];
        let first = page(
            "brain://test",
            &BrainReadTarget {
                item,
                offset: 0,
                limit: 2,
            },
            &chunks,
        )
        .unwrap();
        assert_eq!(first["text"], "a");
        assert_eq!(first["byteEnd"], 1);
        let second = page(
            "brain://test",
            &BrainReadTarget {
                item,
                offset: 1,
                limit: 7,
            },
            &chunks,
        )
        .unwrap();
        assert_eq!(second["text"], "ébcdef");
        assert!(second["continuation"].is_null());
        assert!(page(
            "brain://test",
            &BrainReadTarget {
                item,
                offset: 2,
                limit: 7
            },
            &chunks
        )
        .is_err());
        assert!(page(
            "brain://test",
            &BrainReadTarget {
                item,
                offset: 1,
                limit: 1
            },
            &chunks
        )
        .is_err());
    }
}
