//! Durable operation journal for the sole kernel capability and operation
//! authority.
//!
//! Every row is written inside the caller's immediate transaction; state
//! changes are compare-and-set on the exact `effect_state` they were decided
//! against, so a stale authority never overwrites a newer durable state and a
//! crash between prepare and effect leaves a recoverable nonterminal row.
//! Nonterminal rows — including imported legacy `in_doubt` rows — block their
//! correlation identity until reconciled; nothing is dropped.

mod import_legacy;
mod lease;
mod prepare;
mod row;
mod stop;
mod transition;
mod usage;

pub use import_legacy::{import_legacy_authority, import_receipt_present, LegacyImportCounts};
pub use lease::{
    close_lease, lease_row, open_lease, CapsuleLeaseRow, LeaseAuthority, LeaseOutcome,
};
pub use prepare::{
    nonterminal_rows, operation_row, operation_row_by_id, prepare_operation, rows_for_capsule,
};
pub use row::{
    NewOperation, OperationRow, PrepareOutcome, TransitionOutcome, LEGACY_CAPSULE_ID,
    RECONCILIATION_UNRESOLVABLE,
};
pub use stop::{
    capsule_wide_stop_may_settle, capsule_wide_stop_may_settle_excluding, record_stop, settle_stop,
    stop_intents_for_operation, stop_row, StopRecordOutcome, StopRow, StopSettleOutcome,
};
pub use transition::transition_operation;
pub use usage::{bump_usage, usage, UsageRow};
