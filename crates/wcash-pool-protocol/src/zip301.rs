use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    backend::{
        require_nonzero_hex, validate_bounded_text, validate_v4_header_input, validate_worker_label,
    },
    error::invalid,
    FixedHex, Hex108, Hex1344, Hex24, Hex28, Hex32, Hex4, ProtocolError, TargetBe,
};

/// Maximum miner-facing JSON payload, excluding its final line feed.
pub const MAX_ZIP301_PAYLOAD_BYTES: usize = 64 * 1024;

/// Miner nonce partition selected by a dedicated listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonceProfile {
    /// Four server bytes followed by 28 miner bytes; the stock-ASIC default.
    FourByte,
    /// Eight server bytes followed by 24 miner bytes; opt-in until certified.
    EightByte,
}

impl NonceProfile {
    /// Number of bytes returned by `mining.subscribe`.
    pub const fn prefix_bytes(self) -> usize {
        match self {
            Self::FourByte => 4,
            Self::EightByte => 8,
        }
    }

    /// Number of bytes required in `mining.submit`'s `NONCE_2` field.
    pub const fn suffix_bytes(self) -> usize {
        32 - self.prefix_bytes()
    }
}

/// Server-assigned ZIP-301 nonce prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NoncePrefix {
    /// Four-byte prefix.
    Four(Hex4),
    /// Eight-byte prefix.
    Eight(FixedHex<8>),
}

impl NoncePrefix {
    /// Returns the corresponding listener profile.
    pub const fn profile(&self) -> NonceProfile {
        match self {
            Self::Four(_) => NonceProfile::FourByte,
            Self::Eight(_) => NonceProfile::EightByte,
        }
    }

    /// Returns the exact immutable server nonce-prefix bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Four(value) => value.as_bytes(),
            Self::Eight(value) => value.as_bytes(),
        }
    }

    fn encoded(&self) -> String {
        match self {
            Self::Four(value) => value.to_string(),
            Self::Eight(value) => value.to_string(),
        }
    }
}

/// Miner-controlled ZIP-301 nonce suffix decoded under one listener profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NonceSuffix {
    /// 28-byte suffix paired with a four-byte prefix.
    TwentyEight(Hex28),
    /// 24-byte suffix paired with an eight-byte prefix.
    TwentyFour(Hex24),
}

impl NonceSuffix {
    /// Returns the corresponding listener profile.
    pub const fn profile(&self) -> NonceProfile {
        match self {
            Self::TwentyEight(_) => NonceProfile::FourByte,
            Self::TwentyFour(_) => NonceProfile::EightByte,
        }
    }
}

/// Reconstructs the exact 32-byte header nonce and rejects crossed profiles.
pub fn join_nonce(prefix: &NoncePrefix, suffix: &NonceSuffix) -> Result<Hex32, ProtocolError> {
    let mut nonce = [0; 32];
    match (prefix, suffix) {
        (NoncePrefix::Four(prefix), NonceSuffix::TwentyEight(suffix)) => {
            nonce[..4].copy_from_slice(prefix.as_bytes());
            nonce[4..].copy_from_slice(suffix.as_bytes());
        }
        (NoncePrefix::Eight(prefix), NonceSuffix::TwentyFour(suffix)) => {
            nonce[..8].copy_from_slice(prefix.as_bytes());
            nonce[8..].copy_from_slice(suffix.as_bytes());
        }
        _ => {
            return Err(invalid(
                "ZIP-301 nonce",
                "prefix and suffix use different profiles",
            ))
        }
    }
    Ok(Hex32::new(nonce))
}

/// JSON-RPC identifier accepted from legacy ZIP-301 miners.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Zip301Id {
    /// Unsigned numeric request ID.
    Number(u64),
    /// Bounded string request ID used by some firmware.
    String(String),
    /// Missing/unknown ID used for protocol errors.
    Null(()),
}

impl Zip301Id {
    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Number(_) | Self::Null(()) => Ok(()),
            Self::String(value) => validate_bounded_text(value, 1, 64, "ZIP-301 id"),
        }
    }
}

/// Strictly decoded miner request in the supported ZIP-301 subset.
#[derive(Clone, Eq, PartialEq)]
pub enum Zip301Request {
    /// Starts a session and requests a server nonce prefix.
    Subscribe {
        /// Request identifier.
        id: Zip301Id,
        /// Bounded compatibility parameters, retained for diagnostics only.
        params: Vec<serde_json::Value>,
    },
    /// Associates a worker login with the connection.
    Authorize {
        /// Request identifier.
        id: Zip301Id,
        /// Miner-supplied worker login.
        worker: String,
        /// Miner-supplied pool password; never a payout authorization.
        password: String,
    },
    /// Supplies a non-authoritative preferred target.
    SuggestTarget {
        /// Request identifier.
        id: Zip301Id,
        /// Big-endian 256-bit target suggested by the miner.
        target_be: TargetBe,
    },
    /// Harmless NiceHash capability probe, which the server rejects explicitly.
    ExtranonceSubscribe {
        /// Request identifier.
        id: Zip301Id,
    },
    /// Submits one Equihash solution.
    Submit {
        /// Request identifier.
        id: Zip301Id,
        /// Worker login previously authorized on this connection.
        worker: String,
        /// Exact server-issued job identifier.
        job_id: Hex32,
        /// Exact four raw header time bytes encoded by the job.
        time: Hex4,
        /// Miner-controlled nonce suffix for the listener profile.
        nonce_2: NonceSuffix,
        /// Raw Equihash solution after removing canonical `fd4005` CompactSize.
        solution: Box<Hex1344>,
    },
}

impl fmt::Debug for Zip301Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Subscribe { .. } => formatter
                .debug_struct("Subscribe")
                .field("id", &"[REDACTED]")
                .field("params", &"[REDACTED]")
                .finish(),
            Self::Authorize { .. } => formatter
                .debug_struct("Authorize")
                .field("id", &"[REDACTED]")
                .field("worker", &"[REDACTED]")
                .field("password", &"[REDACTED]")
                .finish(),
            Self::SuggestTarget { target_be, .. } => formatter
                .debug_struct("SuggestTarget")
                .field("id", &"[REDACTED]")
                .field("target_be", target_be)
                .finish(),
            Self::ExtranonceSubscribe { .. } => formatter
                .debug_struct("ExtranonceSubscribe")
                .field("id", &"[REDACTED]")
                .finish(),
            Self::Submit { job_id, time, .. } => formatter
                .debug_struct("Submit")
                .field("id", &"[REDACTED]")
                .field("worker", &"[REDACTED]")
                .field("job_id", job_id)
                .field("time", time)
                .field("nonce_2", &"[REDACTED]")
                .field("solution", &"[REDACTED 1344 bytes]")
                .finish(),
        }
    }
}

impl Zip301Request {
    /// Returns the request ID without re-parsing the original frame.
    pub const fn id(&self) -> &Zip301Id {
        match self {
            Self::Subscribe { id, .. }
            | Self::Authorize { id, .. }
            | Self::SuggestTarget { id, .. }
            | Self::ExtranonceSubscribe { id }
            | Self::Submit { id, .. } => id,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawZip301Request {
    id: Zip301Id,
    method: String,
    params: serde_json::Value,
}

/// Exact fields sent in ZIP-301's eight-parameter work notification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Zip301Notify {
    /// Exact backend generation identifier.
    pub job_id: Hex32,
    /// Exact 108-byte header input split into protocol fields during encoding.
    pub header_input: Hex108,
    /// Whether the ASIC must discard all previous jobs.
    pub clean_jobs: bool,
}

impl Zip301Notify {
    fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero_hex(&self.job_id, "mining.notify job id")?;
        validate_v4_header_input(
            &self.header_input,
            "mining.notify version",
            "mining.notify time",
        )
    }
}

/// Messages emitted by the ZIP-301 edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Zip301ServerMessage {
    /// Successful subscription with one immutable connection prefix.
    Subscribed {
        /// Request identifier copied from the miner.
        id: Zip301Id,
        /// Server nonce prefix.
        nonce_1: NoncePrefix,
    },
    /// Boolean response used by authorization and share submission.
    Boolean {
        /// Request identifier copied from the miner.
        id: Zip301Id,
        /// Result value.
        result: bool,
    },
    /// Standard three-field ZIP-301 error tuple.
    Error {
        /// Request identifier copied from the miner when available.
        id: Zip301Id,
        /// Stable Stratum error code.
        code: i32,
        /// Bounded printable error text.
        message: String,
    },
    /// Assigns a full 256-bit big-endian share target.
    SetTarget {
        /// Target bytes exactly as miners compare them.
        target_be: TargetBe,
    },
    /// Advertises one exact proposal-validated header.
    Notify(Zip301Notify),
}

/// Incremental, bounded decoder for LF-terminated ZIP-301 requests.
///
/// The codec consumes at most one frame per call and reports how many bytes from
/// the supplied slice belong to that frame. Callers can immediately pass the
/// unconsumed suffix back to decode a coalesced frame. Any terminal decode error
/// clears the partial frame, so bytes from a rejected frame cannot be joined to a
/// later request.
pub struct Zip301FrameCodec {
    payload: Vec<u8>,
}

impl fmt::Debug for Zip301FrameCodec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Zip301FrameCodec")
            .field("buffered_bytes", &self.payload.len())
            .finish()
    }
}

impl Default for Zip301FrameCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Zip301FrameCodec {
    /// Creates an empty decoder.
    pub const fn new() -> Self {
        Self {
            payload: Vec::new(),
        }
    }

    /// Returns the number of payload bytes buffered without a terminating LF.
    pub fn buffered_bytes(&self) -> usize {
        self.payload.len()
    }

    /// Discards one incomplete or rejected frame.
    pub fn reset(&mut self) {
        self.payload.clear();
    }

    /// Consumes at most one request from `input` under the listener nonce profile.
    ///
    /// A frame is rejected as soon as its first byte beyond the payload limit is
    /// observed; the codec never buffers that byte or waits for a newline.
    pub fn decode_request(
        &mut self,
        input: &[u8],
        profile: NonceProfile,
    ) -> Result<(usize, Option<Zip301Request>), ProtocolError> {
        let Some(remaining) = MAX_ZIP301_PAYLOAD_BYTES.checked_sub(self.payload.len()) else {
            self.reset();
            return Err(invalid(
                "ZIP-301 decoder",
                "buffer exceeded its payload limit",
            ));
        };
        let inspected = input.len().min(remaining.saturating_add(1));
        let newline = input[..inspected].iter().position(|byte| *byte == b'\n');

        let Some(payload_bytes) = newline else {
            if input.len() > remaining {
                self.reset();
                return Err(ProtocolError::FrameTooLarge {
                    protocol: "ZIP-301",
                    maximum: MAX_ZIP301_PAYLOAD_BYTES,
                    actual: MAX_ZIP301_PAYLOAD_BYTES + 1,
                });
            }
            if self.payload.try_reserve_exact(input.len()).is_err() {
                self.reset();
                return Err(invalid(
                    "ZIP-301 decoder",
                    "could not reserve bounded payload",
                ));
            }
            self.payload.extend_from_slice(input);
            return Ok((input.len(), None));
        };

        if self.payload.try_reserve_exact(payload_bytes + 1).is_err() {
            self.reset();
            return Err(invalid(
                "ZIP-301 decoder",
                "could not reserve bounded payload",
            ));
        }
        self.payload.extend_from_slice(&input[..payload_bytes]);
        self.payload.push(b'\n');
        let frame = std::mem::take(&mut self.payload);
        let decoded = decode_zip301_request(&frame, profile)?;
        Ok((payload_bytes + 1, Some(decoded)))
    }
}

/// Decodes exactly one LF-terminated ZIP-301 request.
///
/// Miner hexadecimal is intentionally case-insensitive for firmware
/// compatibility and is normalized into byte-backed wire types.
pub fn decode_zip301_request(
    frame: &[u8],
    profile: NonceProfile,
) -> Result<Zip301Request, ProtocolError> {
    let payload = zip301_payload(frame)?;
    let raw: RawZip301Request =
        serde_json::from_slice(payload).map_err(|error| ProtocolError::Json(error.to_string()))?;
    raw.id.validate()?;
    if raw.method.len() > 128 || raw.method.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(invalid("ZIP-301 method", "is malformed or too long"));
    }
    let params = raw
        .params
        .as_array()
        .ok_or_else(|| invalid("ZIP-301 params", "must be an array"))?;
    match raw.method.as_str() {
        "mining.subscribe" => {
            validate_subscribe_params(params)?;
            Ok(Zip301Request::Subscribe {
                id: raw.id,
                params: params.clone(),
            })
        }
        "mining.authorize" => {
            require_parameter_count(params, 2, "mining.authorize")?;
            let worker = parameter_string(params, 0, "mining.authorize worker")?;
            validate_worker_label(worker)?;
            let password = parameter_string(params, 1, "mining.authorize password")?;
            validate_bounded_text(password, 0, 1_024, "mining.authorize password")?;
            Ok(Zip301Request::Authorize {
                id: raw.id,
                worker: worker.to_string(),
                password: password.to_string(),
            })
        }
        "mining.suggest_target" => {
            require_parameter_count(params, 1, "mining.suggest_target")?;
            let target = parse_miner_hex::<32>(
                parameter_string(params, 0, "mining.suggest_target target")?,
                "mining.suggest_target target",
            )?;
            require_nonzero_hex(&target, "mining.suggest_target target")?;
            Ok(Zip301Request::SuggestTarget {
                id: raw.id,
                target_be: target.into(),
            })
        }
        "mining.extranonce.subscribe" => {
            require_parameter_count(params, 0, "mining.extranonce.subscribe")?;
            Ok(Zip301Request::ExtranonceSubscribe { id: raw.id })
        }
        "mining.submit" => decode_zip301_submit(raw.id, params, profile),
        _ => Err(ProtocolError::UnsupportedMethod(raw.method)),
    }
}

/// Encodes exactly one LF-terminated ZIP-301 server message.
pub fn encode_zip301_message(message: &Zip301ServerMessage) -> Result<Vec<u8>, ProtocolError> {
    match message {
        Zip301ServerMessage::Subscribed { id, nonce_1 } => {
            id.validate()?;
            let result = serde_json::json!([serde_json::Value::Null, nonce_1.encoded()]);
            encode_zip301_serializable(&Zip301Response {
                id,
                result,
                error: serde_json::Value::Null,
            })
        }
        Zip301ServerMessage::Boolean { id, result } => {
            id.validate()?;
            if !result {
                return Err(invalid(
                    "ZIP-301 boolean response",
                    "false failures must use a typed Error response",
                ));
            }
            encode_zip301_serializable(&Zip301Response {
                id,
                result: serde_json::json!(result),
                error: serde_json::Value::Null,
            })
        }
        Zip301ServerMessage::Error { id, code, message } => {
            id.validate()?;
            validate_bounded_text(message, 1, 256, "ZIP-301 error message")?;
            encode_zip301_serializable(&Zip301Response {
                id,
                result: serde_json::Value::Null,
                error: serde_json::json!([code, message, serde_json::Value::Null]),
            })
        }
        Zip301ServerMessage::SetTarget { target_be } => {
            if target_be.is_zero() {
                return Err(invalid("mining.set_target target", "must be nonzero"));
            }
            encode_zip301_serializable(&Zip301Notification {
                id: serde_json::Value::Null,
                method: "mining.set_target",
                params: serde_json::json!([target_be]),
            })
        }
        Zip301ServerMessage::Notify(notify) => {
            notify.validate()?;
            let input = notify.header_input.as_bytes();
            encode_zip301_serializable(&Zip301Notification {
                id: serde_json::Value::Null,
                method: "mining.notify",
                params: serde_json::json!([
                    notify.job_id,
                    hex::encode(&input[..4]),
                    hex::encode(&input[4..36]),
                    hex::encode(&input[36..68]),
                    hex::encode(&input[68..100]),
                    hex::encode(&input[100..104]),
                    hex::encode(&input[104..108]),
                    notify.clean_jobs,
                ]),
            })
        }
    }
}

fn zip301_payload(frame: &[u8]) -> Result<&[u8], ProtocolError> {
    let Some((&b'\n', payload)) = frame.split_last() else {
        return Err(ProtocolError::InvalidLineFraming);
    };
    if payload.is_empty() {
        return Err(ProtocolError::EmptyFrame {
            protocol: "ZIP-301",
        });
    }
    if payload.len() > MAX_ZIP301_PAYLOAD_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            protocol: "ZIP-301",
            maximum: MAX_ZIP301_PAYLOAD_BYTES,
            actual: payload.len(),
        });
    }
    if payload.iter().any(|byte| matches!(byte, b'\n' | b'\r'))
        || payload.first() != Some(&b'{')
        || payload.last() != Some(&b'}')
    {
        return Err(ProtocolError::InvalidLineFraming);
    }
    Ok(payload)
}

fn decode_zip301_submit(
    id: Zip301Id,
    params: &[serde_json::Value],
    profile: NonceProfile,
) -> Result<Zip301Request, ProtocolError> {
    require_parameter_count(params, 5, "mining.submit")?;
    let worker = parameter_string(params, 0, "mining.submit worker")?;
    validate_worker_label(worker)?;
    let job_id = parse_miner_hex::<32>(
        parameter_string(params, 1, "mining.submit job id")?,
        "mining.submit job id",
    )?;
    require_nonzero_hex(&job_id, "mining.submit job id")?;
    let time = parse_miner_hex::<4>(
        parameter_string(params, 2, "mining.submit time")?,
        "mining.submit time",
    )?;
    require_nonzero_hex(&time, "mining.submit time")?;
    let encoded_nonce = parameter_string(params, 3, "mining.submit nonce_2")?;
    let nonce_2 = match profile {
        NonceProfile::FourByte => NonceSuffix::TwentyEight(parse_miner_hex::<28>(
            encoded_nonce,
            "mining.submit nonce_2",
        )?),
        NonceProfile::EightByte => NonceSuffix::TwentyFour(parse_miner_hex::<24>(
            encoded_nonce,
            "mining.submit nonce_2",
        )?),
    };
    let encoded_solution = parameter_string(params, 4, "mining.submit solution")?;
    let compact_solution = parse_miner_hex::<1347>(encoded_solution, "mining.submit solution")?;
    if compact_solution.as_bytes()[..3] != [0xfd, 0x40, 0x05] {
        return Err(invalid(
            "mining.submit solution",
            "must start with canonical CompactSize fd4005",
        ));
    }
    let solution: [u8; 1_344] = compact_solution.as_bytes()[3..]
        .try_into()
        .map_err(|_| invalid("mining.submit solution", "has an impossible decoded length"))?;
    Ok(Zip301Request::Submit {
        id,
        worker: worker.to_string(),
        job_id,
        time,
        nonce_2,
        solution: Box::new(Hex1344::new(solution)),
    })
}

fn parse_miner_hex<const N: usize>(
    encoded: &str,
    field: &'static str,
) -> Result<FixedHex<N>, ProtocolError> {
    let expected = N
        .checked_mul(2)
        .ok_or_else(|| invalid(field, "encoded length overflowed"))?;
    if encoded.len() != expected {
        return Err(invalid(
            field,
            format!("must contain exactly {expected} hexadecimal characters"),
        ));
    }
    if !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(field, "contains non-hexadecimal characters"));
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(encoded, &mut bytes).map_err(|error| invalid(field, error.to_string()))?;
    Ok(FixedHex::new(bytes))
}

fn validate_subscribe_params(params: &[serde_json::Value]) -> Result<(), ProtocolError> {
    if params.len() > 8 {
        return Err(invalid(
            "mining.subscribe params",
            "must contain at most eight compatibility values",
        ));
    }
    for value in params {
        match value {
            serde_json::Value::Null | serde_json::Value::Number(_) => {}
            serde_json::Value::String(value) => {
                validate_bounded_text(value, 0, 256, "mining.subscribe parameter")?;
            }
            _ => {
                return Err(invalid(
                    "mining.subscribe parameter",
                    "must be null, a number, or a bounded string",
                ))
            }
        }
    }
    Ok(())
}

fn require_parameter_count(
    params: &[serde_json::Value],
    expected: usize,
    method: &'static str,
) -> Result<(), ProtocolError> {
    if params.len() != expected {
        return Err(invalid(
            "ZIP-301 params",
            format!("{method} requires exactly {expected} parameters"),
        ));
    }
    Ok(())
}

fn parameter_string<'a>(
    params: &'a [serde_json::Value],
    index: usize,
    field: &'static str,
) -> Result<&'a str, ProtocolError> {
    params
        .get(index)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid(field, "must be a string"))
}

#[derive(Serialize)]
struct Zip301Response<'a> {
    id: &'a Zip301Id,
    result: serde_json::Value,
    error: serde_json::Value,
}

#[derive(Serialize)]
struct Zip301Notification<'a> {
    id: serde_json::Value,
    method: &'a str,
    params: serde_json::Value,
}

fn encode_zip301_serializable<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let mut payload =
        serde_json::to_vec(value).map_err(|error| ProtocolError::Json(error.to_string()))?;
    if payload.is_empty() {
        return Err(ProtocolError::EmptyFrame {
            protocol: "ZIP-301",
        });
    }
    if payload.len() > MAX_ZIP301_PAYLOAD_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            protocol: "ZIP-301",
            maximum: MAX_ZIP301_PAYLOAD_BYTES,
            actual: payload.len(),
        });
    }
    payload.push(b'\n');
    Ok(payload)
}
