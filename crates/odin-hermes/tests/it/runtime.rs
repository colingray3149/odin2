//! Runtime composition tests for event redelivery, consumed approval requirements, and unavailable surfaces.

#[path = "runtime/cursor.rs"]
mod cursor;
#[path = "runtime/fixtures.rs"]
mod fixtures;
#[path = "runtime/follow_through.rs"]
mod follow_through;
#[path = "runtime/gate.rs"]
mod gate;
#[path = "runtime/intake_route.rs"]
mod intake_route;
#[path = "runtime/jobs.rs"]
mod jobs;
#[path = "runtime/loopback_discord.rs"]
mod loopback_discord;
#[path = "runtime/model_set.rs"]
mod model_set;
#[path = "runtime/notify_schedule.rs"]
mod notify_schedule;
#[path = "runtime/ownership.rs"]
mod ownership;
#[path = "runtime/pump.rs"]
mod pump;
#[path = "runtime/registry_author.rs"]
mod registry_author;
#[path = "runtime/root_consent.rs"]
mod root_consent;
#[path = "runtime/schedule.rs"]
mod schedule;
#[path = "runtime/seats.rs"]
mod seats;
#[path = "runtime/shared_files.rs"]
mod shared_files;
