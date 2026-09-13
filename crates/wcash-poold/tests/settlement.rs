//! Standalone compilation harness for the settlement recovery module.

#![forbid(unsafe_code)]
#![allow(dead_code)]

#[path = "../src/settlement.rs"]
mod settlement;

#[path = "settlement/payout_lifecycle.rs"]
mod payout_lifecycle;
