//! The latest progress line of the call running on this thread, read by the job board.

use std::cell::RefCell;
use std::sync::{Arc, Mutex, PoisonError};

/// Characters of one progress line kept; longer lines are cut.
pub const MAX_LINE_CHARS: usize = 160;

/// One running call's latest progress line, shared between the call and the job board.
#[derive(Clone, Debug, Default)]
pub struct Slot(Arc<Mutex<Option<String>>>);

impl Slot {
    pub fn get(&self) -> Option<String> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set(&self, line: String) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(line);
    }
}

thread_local! {
    static CURRENT: RefCell<Option<Slot>> = const { RefCell::new(None) };
}

/// Restores the thread's previous target when `scoped` returns or unwinds.
struct Restore(Option<Slot>);

impl Drop for Restore {
    fn drop(&mut self) {
        let previous = self.0.take();
        CURRENT.with(|current| *current.borrow_mut() = previous);
    }
}

/// Runs `work` with `slot` as this thread's progress target.
pub fn scoped<T>(slot: Slot, work: impl FnOnce() -> T) -> T {
    let _restore = Restore(CURRENT.with(|current| current.borrow_mut().replace(slot)));
    work()
}

/// Sets the line (at most `MAX_LINE_CHARS` kept); a no-op outside `scoped`.
pub fn report(line: impl Into<String>) {
    CURRENT.with(|current| {
        if let Some(slot) = current.borrow().as_ref() {
            slot.set(line.into().chars().take(MAX_LINE_CHARS).collect());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_outside_scope_is_a_noop() {
        report("ignored");
        let slot = Slot::default();
        scoped(slot.clone(), || report("downloading 41% of 1.2 GB"));
        report("after the scope");
        assert_eq!(slot.get().as_deref(), Some("downloading 41% of 1.2 GB"));
    }
}
