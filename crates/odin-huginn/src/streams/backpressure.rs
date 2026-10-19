use std::collections::VecDeque;

use odin_domain::huginn::{StreamBackpressureLimits, StreamCredit};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreditGrant {
    pub items: u32,
    pub bytes: u64,
}

impl From<StreamCredit> for CreditGrant {
    fn from(credit: StreamCredit) -> Self {
        Self {
            items: credit.items.get(),
            bytes: credit.bytes.get(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreditWindow {
    items: u32,
    bytes: u64,
    max_items: u32,
    max_bytes: u64,
}

impl CreditWindow {
    pub fn new(initial: StreamCredit, limits: StreamBackpressureLimits) -> Self {
        let max_items = limits.max_buffered_items.get();
        let max_bytes = limits.max_in_flight_bytes.get();
        Self {
            items: initial.items.get().min(max_items),
            bytes: initial.bytes.get().min(max_bytes),
            max_items,
            max_bytes,
        }
    }

    pub const fn available(&self) -> CreditGrant {
        CreditGrant {
            items: self.items,
            bytes: self.bytes,
        }
    }

    pub const fn can_send(&self, bytes: u64) -> bool {
        self.items > 0 && self.bytes >= bytes
    }

    pub fn consume(&mut self, bytes: u64) -> bool {
        if !self.can_send(bytes) {
            return false;
        }
        self.items -= 1;
        self.bytes -= bytes;
        true
    }

    pub fn grant(&mut self, grant: CreditGrant) {
        self.items = self.items.saturating_add(grant.items).min(self.max_items);
        self.bytes = self.bytes.saturating_add(grant.bytes).min(self.max_bytes);
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BackpressureError {
    #[error("stream item is {size} bytes; limit is {limit}")]
    ItemTooLarge { size: u64, limit: u64 },
    #[error("subscription buffer overflow")]
    Overflow,
}

pub(crate) struct BoundedQueue<T> {
    items: VecDeque<(T, u64)>,
    bytes: u64,
    max_items: usize,
    max_bytes: u64,
    max_item_bytes: u64,
}

impl<T> BoundedQueue<T> {
    pub(crate) fn new(limits: StreamBackpressureLimits) -> Self {
        Self {
            items: VecDeque::new(),
            bytes: 0,
            max_items: usize::try_from(limits.max_buffered_items.get()).unwrap_or(usize::MAX),
            max_bytes: limits.max_buffered_bytes.get(),
            max_item_bytes: limits.max_item_bytes.get(),
        }
    }

    pub(crate) fn push(&mut self, item: T, bytes: u64) -> Result<(), BackpressureError> {
        if bytes > self.max_item_bytes {
            return Err(BackpressureError::ItemTooLarge {
                size: bytes,
                limit: self.max_item_bytes,
            });
        }
        if self.items.len() >= self.max_items
            || self
                .bytes
                .checked_add(bytes)
                .is_none_or(|total| total > self.max_bytes)
        {
            return Err(BackpressureError::Overflow);
        }
        self.items.push_back((item, bytes));
        self.bytes += bytes;
        Ok(())
    }

    pub(crate) fn replace_latest(
        &mut self,
        item: T,
        bytes: u64,
    ) -> Result<bool, BackpressureError> {
        if bytes > self.max_item_bytes {
            return Err(BackpressureError::ItemTooLarge {
                size: bytes,
                limit: self.max_item_bytes,
            });
        }
        let replaced = self.items.pop_back();
        if let Some((_, prior_bytes)) = replaced.as_ref() {
            self.bytes -= *prior_bytes;
        }
        if self
            .bytes
            .checked_add(bytes)
            .is_none_or(|total| total > self.max_bytes)
        {
            if let Some(prior) = replaced {
                self.bytes += prior.1;
                self.items.push_back(prior);
            }
            return Err(BackpressureError::Overflow);
        }
        self.items.push_back((item, bytes));
        self.bytes += bytes;
        Ok(replaced.is_some())
    }

    pub(crate) fn front_bytes(&self) -> Option<u64> {
        self.items.front().map(|(_, bytes)| *bytes)
    }

    pub(crate) fn pop(&mut self) -> Option<T> {
        self.items.pop_front().map(|(item, bytes)| {
            self.bytes -= bytes;
            item
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) const fn bytes(&self) -> u64 {
        self.bytes
    }
}
