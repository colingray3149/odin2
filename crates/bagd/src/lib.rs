//! bagd device actions: the Flipper serial CLI the fixed argv calls.
//!
//! The daemon and its signed-request pipeline stay in the bagcore checkout.
//! This crate is the declared flash/read executable and the hardware test
//! that exercises the same client.

pub mod flipper;
