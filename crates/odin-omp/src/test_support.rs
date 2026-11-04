//! Shared `#[cfg(test)]` fixture helpers for the `odin_omp` test suites.

use std::sync::{Arc, Mutex};

use odin_ledger::Ledger;

/// Opens a fresh in-memory [`Ledger`] shared behind a mutex.
pub(crate) fn ledger() -> Arc<Mutex<Ledger>> {
    Arc::new(Mutex::new(
        Ledger::open_in_memory().expect("in-memory ledger opens"),
    ))
}
