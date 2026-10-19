//! Runtime composition tests for event redelivery, consumed approval requirements, and unavailable surfaces.

#[path = "runtime/cursor.rs"]
mod cursor;
#[path = "runtime/file_send.rs"]
mod file_send;
#[path = "runtime/fixtures.rs"]
mod fixtures;
#[path = "runtime/gate.rs"]
mod gate;
#[path = "runtime/intake_route.rs"]
mod intake_route;
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
#[path = "runtime/schedule.rs"]
mod schedule;
#[path = "runtime/seats.rs"]
mod seats;
