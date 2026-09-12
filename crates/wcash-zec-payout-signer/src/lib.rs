//! Crash-safe Zcash Testnet payout execution through Zallet PCZTs.
//!
//! The crate never handles spending keys. It drives an isolated Zallet wallet
//! over a bounded RPC interface and asks a parent Zebra node to broadcast only
//! after the exact transaction bytes are durable locally.

#![forbid(unsafe_code)]

mod address;
mod config;
mod error;
mod journal;
mod pipeline;
mod rpc;
mod transport;

pub use config::{validate_zallet_configuration, RpcLimits, ZecSignerConfig, ZALLET_API_VERSION};
pub use error::{PipelineStage, ZecPayoutError};
pub use pipeline::{
    Checkpoint, CheckpointHook, ZecFundSource, ZecPayoutExecution, ZecPayoutRequest, ZecPcztSigner,
};
pub use rpc::{JsonRpcTransport, RpcCall, RpcTransportError};
pub use transport::{LoopbackHttpTransport, LoopbackTransportError};
