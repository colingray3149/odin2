//! Synthetic email/calendar tests for replay, credential isolation, input limits, and JMAP exchanges.
//! Approval-gated send and booking are covered by runtime dispatch and adapter settlement tests.

#[path = "email_calendar/email_lifecycle.rs"]
mod email_lifecycle;
#[path = "email_calendar/fixtures.rs"]
mod fixtures;
#[path = "email_calendar/jmap.rs"]
mod jmap;
#[path = "email_calendar/lease.rs"]
mod lease;
#[path = "email_calendar/settlement.rs"]
mod settlement;
