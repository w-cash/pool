//! Strict wire types shared by the pool edge and the local mining backend.
//!
//! The consensus-sensitive backend protocol uses an exact four-byte,
//! big-endian length prefix. The miner-facing ZIP-301 protocol is deliberately
//! kept separate because it is newline framed and has different compatibility
//! requirements.
//!
//! Decoding a wire value proves only that its syntax and declared invariants are
//! valid. It does not authenticate the sender or prove that a share was durably
//! committed; transport and persistence layers must establish those properties.

#![forbid(unsafe_code)]

mod backend;
mod error;
mod fixed_hex;
mod zip301;

pub use backend::*;
pub use error::ProtocolError;
pub use fixed_hex::*;
pub use zip301::*;

#[cfg(test)]
mod tests;
