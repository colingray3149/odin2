//! Compact in-memory vector index of one immutable generation: the leading
//! dimensions of every stored vector (at most [`COMPACT_DIMS`]; the
//! embedding model is Matryoshka-trained, so a prefix is a coarse embedding
//! of its own), re-normalized and quantized to `i8`. It only nominates
//! candidates; the final score is always the exact full-dimension cosine
//! over the candidates' stored vectors. 256 bytes per chunk keeps a
//! 330k-chunk history near 85 MB.

use odin_domain::knowledge::ids::KnowledgeItemId;

use crate::error::{BrainError, BrainResult};

/// Most prefix dimensions kept per vector.
pub const COMPACT_DIMS: usize = 256;

/// One generation's quantized prefix matrix.
#[derive(Debug, Default)]
pub struct CompactIndex {
    /// Prefix width, fixed by the first row.
    dims: usize,
    ordinals: Vec<i64>,
    items: Vec<KnowledgeItemId>,
    /// Row-major `ordinals.len() × dims` quantized prefixes.
    data: Vec<i8>,
}

/// The re-normalized `width`-dimension prefix of one vector, or `None` when
/// it is too short or has no magnitude.
fn normalized_prefix(dims: &[f32], width: usize) -> Option<Vec<f32>> {
    if width == 0 || dims.len() < width {
        return None;
    }
    let mut prefix = dims[..width].to_vec();
    let norm = prefix.iter().map(|x| x * x).sum::<f32>().sqrt();
    if !norm.is_finite() || norm == 0.0 {
        return None;
    }
    prefix.iter_mut().for_each(|x| *x /= norm);
    Some(prefix)
}

/// A normalized component lies in [-1, 1]: one fixed scale quantizes every
/// row identically, so dot products stay comparable across rows.
fn quantize(x: f32) -> i8 {
    (x * 127.0).round().clamp(-127.0, 127.0) as i8
}

impl CompactIndex {
    pub fn with_capacity(rows: usize) -> Self {
        Self {
            dims: 0,
            ordinals: Vec::with_capacity(rows),
            items: Vec::with_capacity(rows),
            data: Vec::new(),
        }
    }

    /// Adds one stored vector of `item` at `ordinal`.
    pub fn push(&mut self, ordinal: i64, item: KnowledgeItemId, dims: &[f32]) -> BrainResult<()> {
        if self.dims == 0 {
            self.dims = dims.len().min(COMPACT_DIMS);
            self.data.reserve(self.ordinals.capacity() * self.dims);
        }
        let prefix = normalized_prefix(dims, self.dims).ok_or_else(|| BrainError::Corrupt {
            component: "vector_index",
            reason: format!(
                "stored vector {ordinal} has no usable {}-d prefix",
                self.dims
            ),
        })?;
        self.ordinals.push(ordinal);
        self.items.push(item);
        self.data.extend(prefix.iter().copied().map(quantize));
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.ordinals.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ordinals.is_empty()
    }

    /// The ordinals of the `limit` admitted rows nearest the query
    /// embedding, best first. `admit` filters rows by item (serving scope,
    /// project visibility) before they compete.
    pub fn nearest(
        &self,
        query: &[f32],
        limit: usize,
        admit: impl Fn(&KnowledgeItemId) -> bool,
    ) -> Vec<i64> {
        let Some(prefix) = normalized_prefix(query, self.dims) else {
            return Vec::new();
        };
        let query: Vec<i32> = prefix.into_iter().map(|x| i32::from(quantize(x))).collect();
        let mut scored: Vec<(i32, i64)> = self
            .data
            .chunks_exact(self.dims)
            .zip(self.ordinals.iter().zip(&self.items))
            .filter(|(_, (_, item))| admit(item))
            .map(|(row, (ordinal, _))| {
                let dot = row
                    .iter()
                    .zip(&query)
                    .map(|(a, b)| i32::from(*a) * b)
                    .sum::<i32>();
                (dot, *ordinal)
            })
            .collect();
        let limit = limit.min(scored.len());
        if limit == 0 {
            return Vec::new();
        }
        scored.select_nth_unstable_by(limit - 1, |a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        scored.truncate(limit);
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        scored.into_iter().map(|(_, ordinal)| ordinal).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_domain::Digest;

    fn vector(seed: f32) -> Vec<f32> {
        (0..512).map(|i| ((i as f32) * seed).sin()).collect()
    }

    fn item(n: u8) -> KnowledgeItemId {
        KnowledgeItemId::new(Digest::hash(&[n]))
    }

    #[test]
    fn nearest_finds_the_closest_prefix_and_honors_the_filter() {
        let mut index = CompactIndex::with_capacity(4);
        for (ordinal, seed) in [(0, 0.11f32), (1, 0.37), (2, 0.73), (3, 1.31)] {
            index
                .push(ordinal, item(ordinal as u8), &vector(seed))
                .expect("push");
        }
        assert_eq!(index.len(), 4);
        let query = vector(0.73);
        assert_eq!(index.nearest(&query, 1, |_| true), vec![2]);
        assert!(!index.nearest(&query, 4, |id| *id != item(2)).contains(&2));
        assert!(index.nearest(&query, 0, |_| true).is_empty());
        assert!(
            index.push(9, item(9), &[1.0; 8]).is_err(),
            "a row narrower than the index is refused"
        );
    }

    #[test]
    fn narrow_models_index_their_whole_vector() {
        let mut index = CompactIndex::with_capacity(2);
        index.push(0, item(0), &[1.0, 0.0, 0.0]).expect("push");
        index.push(1, item(1), &[0.0, 1.0, 0.0]).expect("push");
        assert_eq!(index.nearest(&[0.0, 0.9, 0.1], 1, |_| true), vec![1]);
    }
}
