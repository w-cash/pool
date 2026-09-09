use thiserror::Error;

/// Errors produced before untrusted wire data reaches pool policy or consensus.
#[derive(Debug, Eq, Error, PartialEq)]
pub enum ProtocolError {
    /// A backend frame did not contain its complete length prefix.
    #[error("backend frame is shorter than its four-byte length prefix")]
    MissingLengthPrefix,
    /// A frame declared an empty payload.
    #[error("{protocol} frame payload must not be empty")]
    EmptyFrame {
        /// Human-readable protocol name.
        protocol: &'static str,
    },
    /// A frame exceeded its protocol's fixed safety bound.
    #[error("{protocol} frame payload is {actual} bytes, maximum is {maximum}")]
    FrameTooLarge {
        /// Human-readable protocol name.
        protocol: &'static str,
        /// Maximum accepted bytes.
        maximum: usize,
        /// Actual or declared bytes.
        actual: usize,
    },
    /// The backend prefix and actual payload length were different.
    #[error("backend frame declares {declared} payload bytes but contains {actual}")]
    InvalidFrameLength {
        /// Length declared by the prefix.
        declared: usize,
        /// Bytes following the prefix.
        actual: usize,
    },
    /// A ZIP-301 frame was not terminated by exactly one line feed.
    #[error("ZIP-301 frame must end in exactly one LF byte")]
    InvalidLineFraming,
    /// JSON syntax or a strict Serde shape was invalid.
    #[error("invalid JSON message: {0}")]
    Json(String),
    /// A syntactically valid message violated a semantic wire invariant.
    #[error("invalid {field}: {reason}")]
    InvalidField {
        /// Stable field name used by diagnostics and tests.
        field: &'static str,
        /// Non-secret failure detail.
        reason: String,
    },
    /// A miner called a method outside the supported ZIP-301 subset.
    #[error("unsupported ZIP-301 method {0:?}")]
    UnsupportedMethod(String),
}

pub(crate) fn invalid(field: &'static str, reason: impl Into<String>) -> ProtocolError {
    ProtocolError::InvalidField {
        field,
        reason: reason.into(),
    }
}
