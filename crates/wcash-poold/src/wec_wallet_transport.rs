//! Integrity-pinned subprocess boundary to Wolf's crash-idempotent payout CLI.

use std::{
    ffi::OsString,
    fs::File,
    io::{Read, Write},
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use wcash_pool_portal::ReceiverKind;
use wcash_wec_payout_signer::{
    BroadcastDisposition, BroadcastFailure, BroadcastOutcome, NativeWalletError,
    NativeWalletTransport, PersistedIntent, SecretSeed, WalletBroadcastCall, WalletFundSource,
    WalletIdentity, WalletInspectionCall, WalletNetwork, WalletOutput, WalletRecoveryCall,
    WalletSignCall, WalletSignedTransaction, WCASH_TESTNET_BRANCH_ID, WCASH_TESTNET_GENESIS_HASH,
};
use zeroize::Zeroizing;

const PAYOUT_PROTOCOL_VERSION: u32 = 1;
const PAYOUT_SIGN_FRAME_MAGIC: &[u8; 16] = b"WCASHPAYSIGNV1\0\0";
const PAYOUT_SIGN_FRAME_HEADER_BYTES: usize = PAYOUT_SIGN_FRAME_MAGIC.len() + 2 + 4;
const MAX_SIGN_REQUEST_BYTES: usize = 512 * 1_024;
const MAX_SECRET_SEED_BYTES: usize = 252;
const MAX_STDERR_BYTES: usize = 64 * 1_024;
const MAX_RAW_TRANSACTION_BYTES: usize = 4_000_000;
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Safe construction failure for the isolated wallet boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WolfTransportConfigError {
    /// The configured program is not an absolute, canonical, protected executable.
    #[error("Wcash wallet executable is unsafe")]
    UnsafeProgram,
    /// The configured executable does not have the reviewed digest.
    #[error("Wcash wallet executable digest does not match")]
    ProgramDigestMismatch,
    /// The wallet database path is not absolute and lexically canonical.
    #[error("Wcash wallet database path is unsafe")]
    UnsafeDatabasePath,
    /// Only a literal loopback plaintext endpoint is accepted at this local boundary.
    #[error("Wcash compact-block endpoint must be literal loopback HTTP")]
    UnsafeEndpoint,
}

/// A canonical executable whose owner, path, mode, inode, and SHA-256 are pinned.
#[derive(Clone)]
pub struct PinnedWolfProgram {
    inner: Arc<PinnedWolfProgramInner>,
}

struct PinnedWolfProgramInner {
    path: PathBuf,
    expected_sha256: [u8; 32],
    trusted_uid: u32,
}

impl PinnedWolfProgram {
    /// Verifies and pins a reviewed `wcash-wallet` executable.
    pub fn verify(
        path: impl Into<PathBuf>,
        expected_sha256: [u8; 32],
        trusted_uid: u32,
    ) -> Result<Self, WolfTransportConfigError> {
        let inner = PinnedWolfProgramInner {
            path: path.into(),
            expected_sha256,
            trusted_uid,
        };
        inner.verify_now()?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    fn path(&self) -> &Path {
        &self.inner.path
    }

    fn verify_now(&self) -> Result<(), WolfTransportConfigError> {
        self.inner.verify_now()
    }
}

impl std::fmt::Debug for PinnedWolfProgram {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PinnedWolfProgram([REDACTED])")
    }
}

impl PinnedWolfProgramInner {
    #[cfg(unix)]
    fn verify_now(&self) -> Result<(), WolfTransportConfigError> {
        if !is_absolute_lexical_path(&self.path)
            || std::fs::canonicalize(&self.path).ok().as_deref() != Some(self.path.as_path())
        {
            return Err(WolfTransportConfigError::UnsafeProgram);
        }
        validate_protected_ancestors(
            self.path
                .parent()
                .ok_or(WolfTransportConfigError::UnsafeProgram)?,
            self.trusted_uid,
        )?;

        let named = std::fs::symlink_metadata(&self.path)
            .map_err(|_| WolfTransportConfigError::UnsafeProgram)?;
        validate_program_metadata(&named, self.trusted_uid)?;
        let mut file =
            File::open(&self.path).map_err(|_| WolfTransportConfigError::UnsafeProgram)?;
        let opened = file
            .metadata()
            .map_err(|_| WolfTransportConfigError::UnsafeProgram)?;
        validate_program_metadata(&opened, self.trusted_uid)?;
        if named.dev() != opened.dev() || named.ino() != opened.ino() {
            return Err(WolfTransportConfigError::UnsafeProgram);
        }

        let mut hasher = Sha256::new();
        std::io::copy(&mut file, &mut hasher)
            .map_err(|_| WolfTransportConfigError::UnsafeProgram)?;
        let after = file
            .metadata()
            .map_err(|_| WolfTransportConfigError::UnsafeProgram)?;
        let renamed = std::fs::symlink_metadata(&self.path)
            .map_err(|_| WolfTransportConfigError::UnsafeProgram)?;
        if opened.dev() != after.dev()
            || opened.ino() != after.ino()
            || opened.len() != after.len()
            || opened.dev() != renamed.dev()
            || opened.ino() != renamed.ino()
            || opened.len() != renamed.len()
        {
            return Err(WolfTransportConfigError::UnsafeProgram);
        }
        let digest: [u8; 32] = hasher.finalize().into();
        if digest != self.expected_sha256 {
            return Err(WolfTransportConfigError::ProgramDigestMismatch);
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn verify_now(&self) -> Result<(), WolfTransportConfigError> {
        Err(WolfTransportConfigError::UnsafeProgram)
    }
}

/// Synchronous, deadline-bounded implementation of Wolf's native payout API.
#[derive(Clone)]
pub struct WolfWalletTransport {
    program: PinnedWolfProgram,
    wallet_database: PathBuf,
    lightwalletd_endpoint: String,
}

impl WolfWalletTransport {
    /// Creates a Testnet-only subprocess boundary.
    pub fn new(
        program: PinnedWolfProgram,
        wallet_database: impl Into<PathBuf>,
        lightwalletd_endpoint: impl Into<String>,
    ) -> Result<Self, WolfTransportConfigError> {
        let wallet_database = wallet_database.into();
        if !is_absolute_lexical_path(&wallet_database) {
            return Err(WolfTransportConfigError::UnsafeDatabasePath);
        }
        let lightwalletd_endpoint = lightwalletd_endpoint.into();
        validate_loopback_endpoint(&lightwalletd_endpoint)?;
        Ok(Self {
            program,
            wallet_database,
            lightwalletd_endpoint,
        })
    }

    fn invoke_wallet(
        &self,
        subcommand: &'static str,
        needs_endpoint: bool,
        input: Zeroizing<Vec<u8>>,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, InvokeError> {
        self.program
            .verify_now()
            .map_err(|_| InvokeError::Preflight)?;
        if timeout.is_zero() || max_response_bytes == 0 {
            return Err(InvokeError::Protocol);
        }
        let mut arguments = vec![
            OsString::from("--network"),
            OsString::from("testnet"),
            OsString::from("--db"),
            self.wallet_database.as_os_str().to_owned(),
        ];
        if needs_endpoint {
            arguments.extend([
                OsString::from("--lightwalletd"),
                OsString::from(&self.lightwalletd_endpoint),
            ]);
        }
        arguments.push(OsString::from(subcommand));
        if subcommand == "payout-sign" {
            arguments.push(OsString::from("--seed-stdin"));
        }
        run_child(
            self.program.path(),
            &arguments,
            input,
            timeout,
            max_response_bytes,
        )
    }

    /// Invokes Wolf's seedless, tip-attested collector observation command.
    ///
    /// The caller remains responsible for validating every response field
    /// against its independently configured wallet authority.
    pub(super) fn invoke_observation(
        &self,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, NativeWalletError> {
        self.invoke_wallet(
            "payout-observe",
            true,
            Zeroizing::new(Vec::new()),
            timeout,
            max_response_bytes,
        )
        .map_err(map_readonly_invoke_error)
    }
}

impl std::fmt::Debug for WolfWalletTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WolfWalletTransport")
            .field("program", &self.program)
            .field("wallet_database", &"[REDACTED]")
            .field("lightwalletd_endpoint", &"[REDACTED]")
            .finish()
    }
}

impl NativeWalletTransport for WolfWalletTransport {
    fn identity(
        &self,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<WalletIdentity, NativeWalletError> {
        let output = self
            .invoke_wallet(
                "payout-identity",
                false,
                Zeroizing::new(Vec::new()),
                timeout,
                max_response_bytes,
            )
            .map_err(map_readonly_invoke_error)?;
        parse_wire_identity(&output)
    }

    fn recover_exact(
        &self,
        call: &WalletRecoveryCall,
    ) -> Result<Option<WalletSignedTransaction>, NativeWalletError> {
        let input = serialize_secret_free(&WireLookup::from(call))?;
        let output = self
            .invoke_wallet(
                "payout-recover",
                false,
                input,
                call.timeout,
                call.max_response_bytes,
            )
            .map_err(map_recovery_invoke_error)?;
        let response: Option<WireSignedPayout> = parse_json(&output)?;
        response
            .map(parse_signed_payout)
            .transpose()
            .map(|value| value.map(|parsed| parsed.transaction))
    }

    fn sign_exact(
        &self,
        call: &WalletSignCall,
        seed: &SecretSeed,
    ) -> Result<WalletSignedTransaction, NativeWalletError> {
        let request = WireSignRequest::from(call);
        let request_json = Zeroizing::new(
            serde_json::to_vec(&request).map_err(|_| NativeWalletError::ProtocolViolation)?,
        );
        let frame = encode_sign_frame(seed.expose_secret(), &request_json)?;
        let output = self
            .invoke_wallet(
                "payout-sign",
                true,
                frame,
                call.timeout,
                call.max_response_bytes,
            )
            .map_err(map_sign_invoke_error)?;
        let parsed = parse_signed_payout(parse_json(&output)?)?;
        if parsed.transaction.batch_id != call.batch_id
            || parsed.transaction.request_commitment != call.request_commitment
            || parsed.identity != call.identity
            || parsed.outputs != call.outputs
        {
            return Err(NativeWalletError::ProtocolViolation);
        }
        Ok(parsed.transaction)
    }

    fn inspect_persisted(
        &self,
        call: &WalletInspectionCall,
    ) -> Result<PersistedIntent, NativeWalletError> {
        let input = serialize_secret_free(&WireInspection::from(call))?;
        let output = self
            .invoke_wallet(
                "payout-inspect",
                false,
                input,
                call.timeout,
                call.max_response_bytes,
            )
            .map_err(map_readonly_invoke_error)?;
        let parsed = parse_signed_payout(parse_json(&output)?)?;
        if parsed.transaction.batch_id != call.batch_id
            || parsed.transaction.request_commitment != call.request_commitment
            || parsed.transaction.transaction_id != call.transaction_id
            || parsed.transaction.raw_transaction_hex != call.raw_transaction_hex
        {
            return Err(NativeWalletError::ProtocolViolation);
        }
        Ok(PersistedIntent {
            identity: parsed.identity,
            batch_id: parsed.transaction.batch_id,
            request_commitment: parsed.transaction.request_commitment,
            ordered_outputs: parsed.outputs,
            unsigned_digest: parsed.transaction.unsigned_digest,
            transaction_id: parsed.transaction.transaction_id,
            raw_transaction_sha256: parsed.raw_transaction_sha256,
            fee_zat: parsed.transaction.fee_zat,
            target_height: parsed.transaction.target_height,
            expiry_height: parsed.transaction.expiry_height,
            stored: parsed.transaction.stored,
            internal_change_receiver_verified: parsed.transaction.internal_change_receiver_verified,
        })
    }

    fn broadcast_exact(
        &self,
        call: &WalletBroadcastCall,
    ) -> Result<BroadcastOutcome, BroadcastFailure> {
        let input = serialize_secret_free(&WireInspection::from(call))
            .map_err(|_| BroadcastFailure::ProtocolViolation)?;
        let output = self
            .invoke_wallet(
                "payout-broadcast",
                true,
                input,
                call.timeout,
                call.max_response_bytes,
            )
            .map_err(map_broadcast_invoke_error)?;
        let response: WireBroadcastResponse =
            parse_json(&output).map_err(|_| BroadcastFailure::ProtocolViolation)?;
        if response.batch_id != call.batch_id.to_string() || response.txid != call.transaction_id {
            return Err(BroadcastFailure::ProtocolViolation);
        }
        let disposition = match response.outcome {
            WireBroadcastOutcome::Accepted { .. } => BroadcastDisposition::Accepted,
            WireBroadcastOutcome::AlreadyKnown { .. } => BroadcastDisposition::AlreadyKnown,
            WireBroadcastOutcome::Rejected { .. } => return Err(BroadcastFailure::Rejected),
            WireBroadcastOutcome::Ambiguous { .. } => return Err(BroadcastFailure::Ambiguous),
        };
        Ok(BroadcastOutcome {
            transaction_id: response.txid,
            disposition,
        })
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WireLookup {
    batch_id: String,
    request_commitment: String,
}

impl From<&WalletRecoveryCall> for WireLookup {
    fn from(call: &WalletRecoveryCall) -> Self {
        Self {
            batch_id: call.batch_id.to_string(),
            request_commitment: hex::encode(call.request_commitment),
        }
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WireInspection<'a> {
    batch_id: String,
    request_commitment: String,
    txid: &'a str,
    raw_transaction_hex: &'a str,
}

impl<'a> From<&'a WalletInspectionCall> for WireInspection<'a> {
    fn from(call: &'a WalletInspectionCall) -> Self {
        Self {
            batch_id: call.batch_id.to_string(),
            request_commitment: hex::encode(call.request_commitment),
            txid: &call.transaction_id,
            raw_transaction_hex: &call.raw_transaction_hex,
        }
    }
}

impl<'a> From<&'a WalletBroadcastCall> for WireInspection<'a> {
    fn from(call: &'a WalletBroadcastCall) -> Self {
        Self {
            batch_id: call.batch_id.to_string(),
            request_commitment: hex::encode(call.request_commitment),
            txid: &call.transaction_id,
            raw_transaction_hex: &call.raw_transaction_hex,
        }
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WireSignRequest<'a> {
    batch_id: String,
    request_commitment: String,
    identity: WireIdentityRef<'a>,
    outputs: Vec<WireOutputRef<'a>>,
    confirmations: u32,
    max_fee_zat: u64,
}

impl<'a> From<&'a WalletSignCall> for WireSignRequest<'a> {
    fn from(call: &'a WalletSignCall) -> Self {
        Self {
            batch_id: call.batch_id.to_string(),
            request_commitment: hex::encode(call.request_commitment),
            identity: WireIdentityRef::from(&call.identity),
            outputs: call.outputs.iter().map(WireOutputRef::from).collect(),
            confirmations: call.confirmations,
            max_fee_zat: call.max_fee_zat,
        }
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WireIdentityRef<'a> {
    protocol_version: u32,
    network: &'static str,
    genesis_hash: &'a str,
    branch_id: &'a str,
    account_id: String,
    fund_source: &'static str,
    synchronized: bool,
}

impl<'a> From<&'a WalletIdentity> for WireIdentityRef<'a> {
    fn from(identity: &'a WalletIdentity) -> Self {
        Self {
            protocol_version: PAYOUT_PROTOCOL_VERSION,
            network: match identity.network {
                WalletNetwork::Testnet => "testnet",
                WalletNetwork::Regtest => "regtest",
                WalletNetwork::Mainnet => "mainnet",
            },
            genesis_hash: &identity.genesis_hash,
            branch_id: &identity.branch_id,
            account_id: identity.account_id.to_string(),
            fund_source: match identity.fund_source {
                WalletFundSource::Ironwood => "ironwood",
                WalletFundSource::Sapling => "sapling",
                WalletFundSource::Transparent => "transparent",
            },
            synchronized: identity.synchronized,
        }
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WireOutputRef<'a> {
    allocation_id: String,
    canonical_address: &'a str,
    receiver_kind: &'static str,
    amount_zat: u64,
    memo_hex: String,
}

impl<'a> From<&'a WalletOutput> for WireOutputRef<'a> {
    fn from(output: &'a WalletOutput) -> Self {
        Self {
            allocation_id: output.allocation_id.to_string(),
            canonical_address: &output.canonical_address,
            receiver_kind: match output.receiver_kind {
                ReceiverKind::Transparent => "transparent",
                ReceiverKind::Ironwood => "ironwood",
            },
            amount_zat: output.amount_zat,
            memo_hex: hex::encode(&output.memo),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireIdentity {
    protocol_version: u32,
    network: String,
    genesis_hash: String,
    branch_id: String,
    account_id: String,
    fund_source: String,
    synchronized: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireOutput {
    allocation_id: String,
    canonical_address: String,
    receiver_kind: String,
    amount_zat: u64,
    memo_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSignedPayout {
    protocol_version: u32,
    batch_id: String,
    request_commitment: String,
    request_facts_digest: String,
    identity: WireIdentity,
    outputs: Vec<WireOutput>,
    txid: String,
    raw_transaction_hex: String,
    raw_transaction_sha256: String,
    unsigned_digest: String,
    branch_id: String,
    target_height: u32,
    expiry_height: u32,
    fee_zat: u64,
    internal_change_receiver_verified: bool,
    stored: bool,
}

struct ParsedSignedPayout {
    transaction: WalletSignedTransaction,
    identity: WalletIdentity,
    outputs: Vec<WalletOutput>,
    raw_transaction_sha256: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBroadcastResponse {
    batch_id: String,
    txid: String,
    outcome: WireBroadcastOutcome,
}

#[derive(Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum WireBroadcastOutcome {
    Accepted {
        #[serde(rename = "status")]
        _status: serde_json::Value,
    },
    AlreadyKnown {
        #[serde(rename = "status")]
        _status: serde_json::Value,
    },
    Rejected {
        #[serde(rename = "code")]
        _code: i32,
        #[serde(rename = "message")]
        _message: String,
    },
    Ambiguous {
        #[serde(rename = "reason")]
        _reason: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireFailure {
    protocol_version: u32,
    code: WireFailureCode,
    error: String,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireFailureCode {
    Rejected,
    Unavailable,
    IdempotencyConflict,
    Ambiguous,
}

fn parse_wire_identity(bytes: &[u8]) -> Result<WalletIdentity, NativeWalletError> {
    parse_identity(parse_json(bytes)?)
}

fn parse_identity(identity: WireIdentity) -> Result<WalletIdentity, NativeWalletError> {
    if identity.protocol_version != PAYOUT_PROTOCOL_VERSION
        || identity.network != "testnet"
        || identity.genesis_hash != WCASH_TESTNET_GENESIS_HASH
        || identity.branch_id != WCASH_TESTNET_BRANCH_ID
        || identity.fund_source != "ironwood"
    {
        return Err(NativeWalletError::ProtocolViolation);
    }
    let account_id = parse_uuid(&identity.account_id)?;
    Ok(WalletIdentity {
        network: WalletNetwork::Testnet,
        genesis_hash: identity.genesis_hash,
        branch_id: identity.branch_id,
        account_id,
        fund_source: WalletFundSource::Ironwood,
        synchronized: identity.synchronized,
    })
}

fn parse_signed_payout(
    response: WireSignedPayout,
) -> Result<ParsedSignedPayout, NativeWalletError> {
    if response.protocol_version != PAYOUT_PROTOCOL_VERSION
        || response.branch_id != WCASH_TESTNET_BRANCH_ID
    {
        return Err(NativeWalletError::ProtocolViolation);
    }
    let identity = parse_identity(response.identity)?;
    let batch_id = parse_uuid(&response.batch_id)?;
    let request_commitment = parse_hex32(&response.request_commitment)?;
    let _request_facts_digest = parse_hex32(&response.request_facts_digest)?;
    let unsigned_digest = parse_hex32(&response.unsigned_digest)?;
    let raw_transaction_sha256 = parse_hex32(&response.raw_transaction_sha256)?;
    validate_lower_hex(&response.txid, 32)?;
    let raw_transaction =
        validate_lower_hex_bounded(&response.raw_transaction_hex, 1, MAX_RAW_TRANSACTION_BYTES)?;
    let computed_raw_sha256: [u8; 32] = Sha256::digest(raw_transaction).into();
    if computed_raw_sha256 != raw_transaction_sha256 {
        return Err(NativeWalletError::ProtocolViolation);
    }
    let outputs = response
        .outputs
        .into_iter()
        .map(parse_output)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ParsedSignedPayout {
        transaction: WalletSignedTransaction {
            batch_id,
            request_commitment,
            transaction_id: response.txid,
            raw_transaction_hex: response.raw_transaction_hex,
            unsigned_digest,
            fee_zat: response.fee_zat,
            target_height: response.target_height,
            expiry_height: response.expiry_height,
            stored: response.stored,
            internal_change_receiver_verified: response.internal_change_receiver_verified,
        },
        identity,
        outputs,
        raw_transaction_sha256,
    })
}

fn parse_output(output: WireOutput) -> Result<WalletOutput, NativeWalletError> {
    if output.receiver_kind != "ironwood"
        || output.canonical_address.len() < 8
        || output.canonical_address.len() > 512
        || output.canonical_address.chars().any(char::is_whitespace)
    {
        return Err(NativeWalletError::ProtocolViolation);
    }
    Ok(WalletOutput {
        allocation_id: parse_uuid(&output.allocation_id)?,
        canonical_address: output.canonical_address,
        receiver_kind: ReceiverKind::Ironwood,
        amount_zat: output.amount_zat,
        memo: validate_lower_hex_bounded(&output.memo_hex, 0, 512)?.to_vec(),
    })
}

fn serialize_secret_free(value: &impl Serialize) -> Result<Zeroizing<Vec<u8>>, NativeWalletError> {
    serde_json::to_vec(value)
        .map(Zeroizing::new)
        .map_err(|_| NativeWalletError::ProtocolViolation)
}

fn parse_json<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, NativeWalletError> {
    serde_json::from_slice(bytes).map_err(|_| NativeWalletError::ProtocolViolation)
}

fn parse_uuid(value: &str) -> Result<Uuid, NativeWalletError> {
    let parsed = Uuid::parse_str(value).map_err(|_| NativeWalletError::ProtocolViolation)?;
    if parsed.is_nil() || parsed.to_string() != value {
        return Err(NativeWalletError::ProtocolViolation);
    }
    Ok(parsed)
}

fn parse_hex32(value: &str) -> Result<[u8; 32], NativeWalletError> {
    validate_lower_hex(value, 32)?
        .try_into()
        .map_err(|_| NativeWalletError::ProtocolViolation)
}

fn validate_lower_hex(value: &str, decoded_bytes: usize) -> Result<Vec<u8>, NativeWalletError> {
    validate_lower_hex_bounded(value, decoded_bytes, decoded_bytes).map(|decoded| decoded.to_vec())
}

fn validate_lower_hex_bounded(
    value: &str,
    minimum_decoded_bytes: usize,
    maximum_decoded_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, NativeWalletError> {
    if !value.len().is_multiple_of(2)
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(NativeWalletError::ProtocolViolation);
    }
    let decoded =
        Zeroizing::new(hex::decode(value).map_err(|_| NativeWalletError::ProtocolViolation)?);
    if !(minimum_decoded_bytes..=maximum_decoded_bytes).contains(&decoded.len()) {
        return Err(NativeWalletError::ProtocolViolation);
    }
    Ok(decoded)
}

fn encode_sign_frame(
    seed: &[u8],
    request_json: &[u8],
) -> Result<Zeroizing<Vec<u8>>, NativeWalletError> {
    if seed.len() < 32
        || seed.len() > MAX_SECRET_SEED_BYTES
        || request_json.is_empty()
        || request_json.len() > MAX_SIGN_REQUEST_BYTES
    {
        return Err(NativeWalletError::ProtocolViolation);
    }
    let seed_length =
        u16::try_from(seed.len()).map_err(|_| NativeWalletError::ProtocolViolation)?;
    let request_length =
        u32::try_from(request_json.len()).map_err(|_| NativeWalletError::ProtocolViolation)?;
    let mut frame = Zeroizing::new(Vec::with_capacity(
        PAYOUT_SIGN_FRAME_HEADER_BYTES + seed.len() + request_json.len(),
    ));
    frame.extend_from_slice(PAYOUT_SIGN_FRAME_MAGIC);
    frame.extend_from_slice(&seed_length.to_be_bytes());
    frame.extend_from_slice(&request_length.to_be_bytes());
    frame.extend_from_slice(seed);
    frame.extend_from_slice(request_json);
    Ok(frame)
}

#[derive(Clone, Copy, Debug)]
enum InvokeError {
    Preflight,
    Spawn,
    TimedOut,
    InputOutput,
    ResponseLimit,
    Protocol,
    Exited(Option<WireFailureCode>),
}

fn run_child(
    program: &Path,
    arguments: &[OsString],
    input: Zeroizing<Vec<u8>>,
    timeout: Duration,
    max_response_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, InvokeError> {
    let mut command = Command::new(program);
    command
        .args(arguments)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|_| InvokeError::Spawn)?;
    let Some(stdin) = child.stdin.take() else {
        terminate_child(&mut child);
        return Err(InvokeError::InputOutput);
    };
    let Some(stdout) = child.stdout.take() else {
        terminate_child(&mut child);
        return Err(InvokeError::InputOutput);
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_child(&mut child);
        return Err(InvokeError::InputOutput);
    };

    let input_writer = match thread::Builder::new()
        .name("wcash-wallet-stdin".to_owned())
        .spawn(move || write_private_input(stdin, input))
    {
        Ok(handle) => handle,
        Err(_) => {
            terminate_child(&mut child);
            return Err(InvokeError::InputOutput);
        }
    };
    let output_reader = match thread::Builder::new()
        .name("wcash-wallet-stdout".to_owned())
        .spawn(move || read_bounded(stdout, max_response_bytes))
    {
        Ok(handle) => handle,
        Err(_) => {
            terminate_child(&mut child);
            let _ = input_writer.join();
            return Err(InvokeError::InputOutput);
        }
    };
    let error_reader = match thread::Builder::new()
        .name("wcash-wallet-stderr".to_owned())
        .spawn(move || read_bounded(stderr, MAX_STDERR_BYTES))
    {
        Ok(handle) => handle,
        Err(_) => {
            terminate_child(&mut child);
            let _ = input_writer.join();
            let _ = output_reader.join();
            return Err(InvokeError::InputOutput);
        }
    };

    let status = wait_with_deadline(&mut child, timeout);
    let input_result = input_writer.join().map_err(|_| InvokeError::InputOutput)?;
    let output = output_reader
        .join()
        .map_err(|_| InvokeError::InputOutput)??;
    let error = error_reader
        .join()
        .map_err(|_| InvokeError::InputOutput)??;
    let status = status?;
    if output.exceeded || error.exceeded {
        return Err(InvokeError::ResponseLimit);
    }
    if !status.success() {
        let failure = serde_json::from_slice::<WireFailure>(&error.bytes)
            .ok()
            .filter(|failure| {
                failure.protocol_version == PAYOUT_PROTOCOL_VERSION && !failure.error.is_empty()
            })
            .map(|failure| failure.code);
        return Err(InvokeError::Exited(failure));
    }
    // A successful machine-protocol command has no diagnostic channel. Treat
    // any stderr as a protocol violation so warnings cannot be silently mixed
    // with a response from an unexpected or partially compatible executable.
    if !error.bytes.is_empty() {
        return Err(InvokeError::Protocol);
    }
    input_result.map_err(|_| InvokeError::InputOutput)?;
    if output.bytes.is_empty() {
        return Err(InvokeError::Protocol);
    }
    Ok(output.bytes)
}

fn write_private_input(
    mut stdin: impl Write,
    input: Zeroizing<Vec<u8>>,
) -> Result<(), std::io::Error> {
    stdin.write_all(&input)?;
    stdin.flush()
}

struct BoundedRead {
    bytes: Zeroizing<Vec<u8>>,
    exceeded: bool,
}

fn read_bounded(mut reader: impl Read, maximum: usize) -> Result<BoundedRead, InvokeError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(maximum.min(64 * 1_024)));
    let mut exceeded = false;
    let mut chunk = [0_u8; 8 * 1_024];
    loop {
        let count = reader
            .read(&mut chunk)
            .map_err(|_| InvokeError::InputOutput)?;
        if count == 0 {
            break;
        }
        let remaining = maximum.saturating_sub(bytes.len());
        let retained = remaining.min(count);
        bytes.extend_from_slice(&chunk[..retained]);
        exceeded |= retained != count;
    }
    Ok(BoundedRead { bytes, exceeded })
}

fn wait_with_deadline(child: &mut Child, timeout: Duration) -> Result<ExitStatus, InvokeError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(InvokeError::Protocol)?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(_) => {
                terminate_child(child);
                return Err(InvokeError::InputOutput);
            }
        }
        let now = Instant::now();
        if now >= deadline {
            terminate_child(child);
            return Err(InvokeError::TimedOut);
        }
        thread::sleep(CHILD_POLL_INTERVAL.min(deadline.saturating_duration_since(now)));
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn map_readonly_invoke_error(error: InvokeError) -> NativeWalletError {
    match error {
        InvokeError::TimedOut => NativeWalletError::Timeout,
        InvokeError::Preflight | InvokeError::Spawn | InvokeError::InputOutput => {
            NativeWalletError::Unavailable
        }
        InvokeError::Exited(Some(WireFailureCode::IdempotencyConflict)) => {
            NativeWalletError::IdempotencyConflict
        }
        InvokeError::Exited(Some(WireFailureCode::Unavailable)) => NativeWalletError::Unavailable,
        InvokeError::Exited(Some(WireFailureCode::Ambiguous)) => NativeWalletError::Ambiguous,
        InvokeError::Exited(Some(WireFailureCode::Rejected)) => NativeWalletError::Rejected,
        InvokeError::ResponseLimit | InvokeError::Protocol | InvokeError::Exited(None) => {
            NativeWalletError::ProtocolViolation
        }
    }
}

fn map_recovery_invoke_error(error: InvokeError) -> NativeWalletError {
    match error {
        InvokeError::Exited(None) | InvokeError::ResponseLimit => NativeWalletError::Ambiguous,
        other => map_readonly_invoke_error(other),
    }
}

fn map_sign_invoke_error(error: InvokeError) -> NativeWalletError {
    match error {
        InvokeError::Preflight | InvokeError::Spawn => NativeWalletError::Unavailable,
        InvokeError::Exited(Some(WireFailureCode::IdempotencyConflict)) => {
            NativeWalletError::IdempotencyConflict
        }
        InvokeError::Exited(Some(WireFailureCode::Rejected)) => NativeWalletError::Rejected,
        InvokeError::Exited(Some(WireFailureCode::Unavailable))
        | InvokeError::Exited(Some(WireFailureCode::Ambiguous))
        | InvokeError::Exited(None)
        | InvokeError::TimedOut
        | InvokeError::InputOutput
        | InvokeError::ResponseLimit
        | InvokeError::Protocol => NativeWalletError::Ambiguous,
    }
}

fn map_broadcast_invoke_error(error: InvokeError) -> BroadcastFailure {
    match error {
        InvokeError::TimedOut => BroadcastFailure::Timeout,
        InvokeError::Preflight | InvokeError::Spawn => BroadcastFailure::Unavailable,
        InvokeError::Exited(Some(WireFailureCode::Rejected)) => BroadcastFailure::Rejected,
        InvokeError::Protocol => BroadcastFailure::ProtocolViolation,
        InvokeError::InputOutput | InvokeError::ResponseLimit | InvokeError::Exited(_) => {
            BroadcastFailure::Ambiguous
        }
    }
}

fn is_absolute_lexical_path(path: &Path) -> bool {
    path.is_absolute()
        && path.file_name().is_some()
        && !path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        && PathBuf::from_iter(path.components()) == path
}

fn validate_loopback_endpoint(endpoint: &str) -> Result<(), WolfTransportConfigError> {
    let authority = endpoint
        .strip_prefix("http://")
        .ok_or(WolfTransportConfigError::UnsafeEndpoint)?;
    if authority.contains(['/', '?', '#', '@']) || authority.chars().any(char::is_whitespace) {
        return Err(WolfTransportConfigError::UnsafeEndpoint);
    }
    let address: SocketAddr = authority
        .parse()
        .map_err(|_| WolfTransportConfigError::UnsafeEndpoint)?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(WolfTransportConfigError::UnsafeEndpoint);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_program_metadata(
    metadata: &std::fs::Metadata,
    trusted_uid: u32,
) -> Result<(), WolfTransportConfigError> {
    let mode = metadata.permissions().mode();
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != trusted_uid
        || mode & 0o022 != 0
        || mode & 0o111 == 0
        || mode & 0o7000 != 0
        || metadata.len() == 0
    {
        return Err(WolfTransportConfigError::UnsafeProgram);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_protected_ancestors(
    starting_directory: &Path,
    trusted_uid: u32,
) -> Result<(), WolfTransportConfigError> {
    let mut current = Some(starting_directory);
    while let Some(directory) = current {
        let metadata = std::fs::symlink_metadata(directory)
            .map_err(|_| WolfTransportConfigError::UnsafeProgram)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || (metadata.uid() != 0 && metadata.uid() != trusted_uid)
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(WolfTransportConfigError::UnsafeProgram);
        }
        current = directory.parent();
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    const TEST_PROCESS_TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn loopback_endpoint_is_literal_and_has_no_url_ambiguity() {
        assert!(validate_loopback_endpoint("http://127.0.0.1:38234").is_ok());
        assert!(validate_loopback_endpoint("http://[::1]:38234").is_ok());
        for unsafe_endpoint in [
            "https://127.0.0.1:38234",
            "http://localhost:38234",
            "http://127.0.0.1:0",
            "http://127.0.0.1:38234/path",
            "http://user@127.0.0.1:38234",
            "http://76.13.10.156:38234",
        ] {
            assert_eq!(
                validate_loopback_endpoint(unsafe_endpoint),
                Err(WolfTransportConfigError::UnsafeEndpoint)
            );
        }
    }

    #[test]
    fn signing_frame_has_exact_public_header_and_raw_private_seed() {
        let seed = [0x7c; 32];
        let request = br#"{"batch_id":"fixture"}"#;
        let frame = encode_sign_frame(&seed, request).unwrap();
        assert_eq!(&frame[..16], PAYOUT_SIGN_FRAME_MAGIC);
        assert_eq!(u16::from_be_bytes([frame[16], frame[17]]), 32);
        assert_eq!(
            u32::from_be_bytes([frame[18], frame[19], frame[20], frame[21]]),
            request.len() as u32
        );
        assert_eq!(&frame[22..54], &seed);
        assert_eq!(&frame[54..], request);
    }

    #[test]
    fn signed_response_rejects_raw_transaction_digest_mismatch() {
        let response = WireSignedPayout {
            protocol_version: PAYOUT_PROTOCOL_VERSION,
            batch_id: "10000000-0000-4000-8000-000000000001".to_owned(),
            request_commitment: "11".repeat(32),
            request_facts_digest: "22".repeat(32),
            identity: WireIdentity {
                protocol_version: PAYOUT_PROTOCOL_VERSION,
                network: "testnet".to_owned(),
                genesis_hash: WCASH_TESTNET_GENESIS_HASH.to_owned(),
                branch_id: WCASH_TESTNET_BRANCH_ID.to_owned(),
                account_id: "20000000-0000-4000-8000-000000000002".to_owned(),
                fund_source: "ironwood".to_owned(),
                synchronized: true,
            },
            outputs: vec![WireOutput {
                allocation_id: "30000000-0000-4000-8000-000000000003".to_owned(),
                canonical_address: "wutest1privatefixture".to_owned(),
                receiver_kind: "ironwood".to_owned(),
                amount_zat: 1,
                memo_hex: String::new(),
            }],
            txid: "33".repeat(32),
            raw_transaction_hex: "0102".to_owned(),
            raw_transaction_sha256: "44".repeat(32),
            unsigned_digest: "55".repeat(32),
            branch_id: WCASH_TESTNET_BRANCH_ID.to_owned(),
            target_height: 100,
            expiry_height: 140,
            fee_zat: 10_000,
            internal_change_receiver_verified: true,
            stored: true,
        };
        assert!(matches!(
            parse_signed_payout(response),
            Err(NativeWalletError::ProtocolViolation)
        ));
    }

    #[test]
    fn debug_output_redacts_program_and_runtime_paths() {
        let value = format!(
            "{:?}",
            PinnedWolfProgram {
                inner: Arc::new(PinnedWolfProgramInner {
                    path: PathBuf::from("/secret/wcash-wallet"),
                    expected_sha256: [7; 32],
                    trusted_uid: 42,
                }),
            }
        );
        assert_eq!(value, "PinnedWolfProgram([REDACTED])");
    }

    #[cfg(unix)]
    fn fixture_transport(shell_body: &str) -> (tempfile::TempDir, PathBuf, WolfWalletTransport) {
        let directory = tempfile::tempdir().unwrap();
        let canonical_directory = std::fs::canonicalize(directory.path()).unwrap();
        let program_path = canonical_directory.join("wcash-wallet-fixture");
        std::fs::write(&program_path, format!("#!/bin/sh\n{shell_body}\n")).unwrap();
        std::fs::set_permissions(&program_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = std::fs::metadata(&program_path).unwrap();
        let digest: [u8; 32] = Sha256::digest(std::fs::read(&program_path).unwrap()).into();
        let program = PinnedWolfProgram::verify(&program_path, digest, metadata.uid()).unwrap();
        let transport = WolfWalletTransport::new(
            program,
            canonical_directory.join("wallet.sqlite"),
            "http://127.0.0.1:38234",
        )
        .unwrap();
        (directory, program_path, transport)
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_identity_is_bounded_and_testnet_attested() {
        let identity = serde_json::json!({
            "protocol_version": 1,
            "network": "testnet",
            "genesis_hash": WCASH_TESTNET_GENESIS_HASH,
            "branch_id": WCASH_TESTNET_BRANCH_ID,
            "account_id": "10000000-0000-4000-8000-000000000001",
            "fund_source": "ironwood",
            "synchronized": true
        });
        let script = format!(
            "case \" $* \" in\n  *\" payout-identity \"*) printf '%s' '{}' ;;\n  *) exit 64 ;;\nesac",
            identity
        );
        let (_directory, _program, transport) = fixture_transport(&script);
        let observed = transport.identity(TEST_PROCESS_TIMEOUT, 4_096).unwrap();
        assert_eq!(observed.network, WalletNetwork::Testnet);
        assert_eq!(observed.genesis_hash, WCASH_TESTNET_GENESIS_HASH);
        assert_eq!(observed.branch_id, WCASH_TESTNET_BRANCH_ID);
        assert_eq!(
            observed.account_id,
            Uuid::parse_str("10000000-0000-4000-8000-000000000001").unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_receives_private_frame_only_on_stdin() {
        let directory = tempfile::tempdir().unwrap();
        let canonical_directory = std::fs::canonicalize(directory.path()).unwrap();
        let capture = canonical_directory.join("captured-frame");
        let quoted_capture = capture.to_string_lossy().replace('\'', "'\\''");
        let script = format!(
            "case \" $* \" in\n  *\" payout-sign --seed-stdin \"*) /bin/cat > '{quoted_capture}'; printf '%s' '{{}}' ;;\n  *) exit 64 ;;\nesac"
        );
        let program_path = canonical_directory.join("wcash-wallet-fixture");
        std::fs::write(&program_path, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&program_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = std::fs::metadata(&program_path).unwrap();
        let digest: [u8; 32] = Sha256::digest(std::fs::read(&program_path).unwrap()).into();
        let transport = WolfWalletTransport::new(
            PinnedWolfProgram::verify(&program_path, digest, metadata.uid()).unwrap(),
            canonical_directory.join("wallet.sqlite"),
            "http://127.0.0.1:38234",
        )
        .unwrap();
        let private_frame = Zeroizing::new(vec![0xa5; 257]);
        let output = transport
            .invoke_wallet(
                "payout-sign",
                true,
                private_frame.clone(),
                TEST_PROCESS_TIMEOUT,
                1_024,
            )
            .unwrap();
        assert_eq!(&*output, b"{}");
        assert_eq!(std::fs::read(capture).unwrap(), *private_frame);
    }

    #[cfg(unix)]
    #[test]
    fn executable_mutation_fails_before_a_second_wallet_call() {
        let identity = serde_json::json!({
            "protocol_version": 1,
            "network": "testnet",
            "genesis_hash": WCASH_TESTNET_GENESIS_HASH,
            "branch_id": WCASH_TESTNET_BRANCH_ID,
            "account_id": "10000000-0000-4000-8000-000000000001",
            "fund_source": "ironwood",
            "synchronized": true
        });
        let script = format!("printf '%s' '{}'", identity);
        let (_directory, program, transport) = fixture_transport(&script);
        assert!(transport.identity(TEST_PROCESS_TIMEOUT, 4_096).is_ok());
        std::fs::write(&program, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            transport.identity(TEST_PROCESS_TIMEOUT, 4_096),
            Err(NativeWalletError::Unavailable)
        );
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_deadline_kills_a_stalled_wallet() {
        let (_directory, _program, transport) = fixture_transport("exec /bin/sleep 5");
        let started = Instant::now();
        assert_eq!(
            transport.identity(Duration::from_millis(25), 4_096),
            Err(NativeWalletError::Timeout)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_failure_code_preserves_idempotency_conflicts() {
        let failure = serde_json::json!({
            "protocol_version": 1,
            "code": "idempotency_conflict",
            "error": "fixture conflict"
        });
        let script = format!("printf '%s' '{}' >&2; exit 1", failure);
        let (_directory, _program, transport) = fixture_transport(&script);
        assert_eq!(
            transport.identity(TEST_PROCESS_TIMEOUT, 4_096),
            Err(NativeWalletError::IdempotencyConflict)
        );
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_output_above_caller_limit_fails_closed() {
        let oversized = "a".repeat(2_048);
        let script = format!("printf '%s' '{oversized}'");
        let (_directory, _program, transport) = fixture_transport(&script);
        assert_eq!(
            transport.identity(TEST_PROCESS_TIMEOUT, 1_024),
            Err(NativeWalletError::ProtocolViolation)
        );
    }

    #[cfg(unix)]
    #[test]
    fn executable_mode_and_digest_are_both_enforced() {
        let directory = tempfile::tempdir().unwrap();
        let canonical_directory = std::fs::canonicalize(directory.path()).unwrap();
        let program = canonical_directory.join("wcash-wallet-fixture");
        std::fs::write(&program, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o722)).unwrap();
        let metadata = std::fs::metadata(&program).unwrap();
        let digest: [u8; 32] = Sha256::digest(std::fs::read(&program).unwrap()).into();
        assert!(matches!(
            PinnedWolfProgram::verify(&program, digest, metadata.uid()),
            Err(WolfTransportConfigError::UnsafeProgram)
        ));

        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            PinnedWolfProgram::verify(&program, [0; 32], metadata.uid()),
            Err(WolfTransportConfigError::ProgramDigestMismatch)
        ));
    }
}
