//! Bounded JSON-RPC transport contract.

use std::{fmt, time::Duration};

use serde_json::Value;

const MAX_SERVER_ERROR_BYTES: usize = 512;

/// One timeout- and response-bounded JSON-RPC call.
pub struct RpcCall {
    method: &'static str,
    params: Value,
    timeout: Duration,
    max_response_bytes: usize,
}

impl RpcCall {
    pub(crate) fn new(
        method: &'static str,
        params: Value,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Self {
        Self {
            method,
            params,
            timeout,
            max_response_bytes,
        }
    }

    /// Returns the pinned JSON-RPC method name.
    pub const fn method(&self) -> &'static str {
        self.method
    }

    /// Returns the positional JSON-RPC parameters.
    ///
    /// Callers must not log this value: it can contain payout addresses, raw
    /// transactions, or a PCZT.
    pub const fn params(&self) -> &Value {
        &self.params
    }

    /// Returns the maximum wall-clock duration allowed for the call.
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Returns the maximum accepted serialized result size.
    pub const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }
}

impl fmt::Debug for RpcCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RpcCall")
            .field("method", &self.method)
            .field("params", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
enum RpcFailure {
    Timeout,
    Unavailable,
    ResponseTooLarge,
    Server { code: i64, message: String },
}

/// Transport failure with server text redacted from `Debug` and `Display`.
#[derive(Clone, Eq, PartialEq)]
pub struct RpcTransportError {
    failure: RpcFailure,
}

impl RpcTransportError {
    /// Creates a deadline-exceeded failure.
    pub const fn timeout() -> Self {
        Self {
            failure: RpcFailure::Timeout,
        }
    }

    /// Creates a connection or service availability failure.
    pub const fn unavailable() -> Self {
        Self {
            failure: RpcFailure::Unavailable,
        }
    }

    /// Creates a response-size violation.
    pub const fn response_too_large() -> Self {
        Self {
            failure: RpcFailure::ResponseTooLarge,
        }
    }

    /// Creates a bounded JSON-RPC server error.
    ///
    /// The message is retained only so the parent-node adapter can recognize
    /// standard duplicate-transaction responses. It is never exposed by this
    /// crate's formatting or payout errors.
    pub fn server(code: i64, message: impl Into<String>) -> Self {
        let mut message = message.into();
        if message.len() > MAX_SERVER_ERROR_BYTES {
            let mut boundary = MAX_SERVER_ERROR_BYTES;
            while !message.is_char_boundary(boundary) {
                boundary -= 1;
            }
            message.truncate(boundary);
        }
        Self {
            failure: RpcFailure::Server { code, message },
        }
    }

    pub(crate) const fn is_server(&self) -> bool {
        matches!(self.failure, RpcFailure::Server { .. })
    }

    pub(crate) fn is_already_known(&self) -> bool {
        let RpcFailure::Server { code, message } = &self.failure else {
            return false;
        };
        if !matches!(*code, -26 | -27) {
            return false;
        }
        let message = message.to_ascii_lowercase();
        message.contains("already")
            && (message.contains("known")
                || message.contains("mempool")
                || message.contains("block chain")
                || message.contains("blockchain"))
    }

    pub(crate) const fn is_explicit_validation_rejection(&self) -> bool {
        matches!(
            self.failure,
            RpcFailure::Server {
                code: -22 | -25 | -26,
                ..
            }
        )
    }
}

impl fmt::Debug for RpcTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.failure {
            RpcFailure::Timeout => "timeout",
            RpcFailure::Unavailable => "unavailable",
            RpcFailure::ResponseTooLarge => "response_too_large",
            RpcFailure::Server { .. } => "server_error",
        };
        formatter
            .debug_struct("RpcTransportError")
            .field("kind", &kind)
            .finish()
    }
}

impl fmt::Display for RpcTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON-RPC transport failed")
    }
}

impl std::error::Error for RpcTransportError {}

/// Abstract JSON-RPC transport used for both loopback Zallet and parent Zebra.
///
/// Implementations must enforce both limits carried by [`RpcCall`] before
/// returning a fully buffered result. Authentication secrets belong inside the
/// transport implementation and must never be embedded in a call value.
pub trait JsonRpcTransport: Send + Sync {
    /// Performs one call and returns only its JSON-RPC `result` value.
    fn call(&self, call: RpcCall) -> Result<Value, RpcTransportError>;
}
