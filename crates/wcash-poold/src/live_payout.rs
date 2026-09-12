//! Authenticated live wallet and validator adapters for automatic payouts.

use std::{
    collections::HashSet,
    fmt,
    future::Future,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time,
};
use uuid::Uuid;
use wcash_pool_store::{
    Chain, PayoutBatchState, PayoutConfirmation, PayoutReorg, PayoutWatch, SignedPayoutArtifact,
    WalletObservation,
};
use wcash_wec_payout_signer::WCASH_TESTNET_BRANCH_ID;
use wcash_zec_payout_signer::validated_parent_payout_address_commitment;
use zeroize::{Zeroize, Zeroizing};
use zip32::fingerprint::SeedFingerprint;

use crate::{
    config::read_protected,
    payout_runtime::{
        AuthorityPayoutObservation, AuthorityPayoutState, AuthoritySnapshot, ObservationFailure,
        ObservationFuture, PayoutConfirmationAuthority, WalletObservationSource,
    },
    settlement::{BoundaryFailure, BoundaryFuture, ExactTransactionBroadcaster},
};

pub(crate) const ZCASH_NU6_3_BRANCH_ID: &str = "37a5165b";
const WALLET_OBSERVATION_DOMAIN: &[u8] = b"ZECWEC-ZALLET-OBSERVATION-V2\0";
const OBSERVATION_VALIDITY_SECS: u64 = 4 * 60;
const MAX_COOKIE_BYTES: u64 = 1_024;
const MAX_HEADER_BYTES: usize = 32 * 1_024;
const MAX_REQUEST_BYTES: usize = 16 * 1_024 * 1_024;
const MAX_ENVELOPE_OVERHEAD: usize = 64 * 1_024;
const MAX_TRANSACTION_BYTES: usize = 4 * 1_024 * 1_024;

type RpcFuture<'a> = Pin<Box<dyn Future<Output = Result<Value, RpcFailure>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RpcFailure {
    Timeout,
    Unavailable,
    ResponseTooLarge,
    Protocol,
    Server(i64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RpcLimits {
    timeout: Duration,
    maximum_response_bytes: usize,
}

impl RpcLimits {
    const fn ordinary() -> Self {
        Self {
            timeout: Duration::from_secs(15),
            maximum_response_bytes: 10 * 1024 * 1024,
        }
    }

    const fn compact() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            maximum_response_bytes: 256 * 1024,
        }
    }
}

trait BoundedRpcClient: Send + Sync {
    fn call(&self, method: &'static str, params: Value, limits: RpcLimits) -> RpcFuture<'_>;
}

/// A minimal authenticated JSON-RPC client which can only connect to a literal
/// loopback socket and reloads its protected cookie on every request.
#[derive(Clone)]
pub(crate) struct LoopbackJsonRpc {
    endpoint: SocketAddr,
    cookie_file: PathBuf,
    next_request_id: Arc<AtomicU64>,
}

impl LoopbackJsonRpc {
    pub(crate) fn new(
        endpoint: SocketAddr,
        cookie_file: impl Into<PathBuf>,
    ) -> Result<Self, LivePayoutConfigError> {
        let cookie_file = cookie_file.into();
        if !endpoint.ip().is_loopback() || endpoint.port() == 0 || !cookie_file.is_absolute() {
            return Err(LivePayoutConfigError::UnsafeRpcBoundary);
        }
        read_rpc_cookie(&cookie_file).map_err(|_| LivePayoutConfigError::UnsafeRpcBoundary)?;
        Ok(Self {
            endpoint,
            cookie_file,
            next_request_id: Arc::new(AtomicU64::new(1)),
        })
    }

    fn allocate_request_id(&self) -> Result<u64, RpcFailure> {
        self.next_request_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| RpcFailure::Unavailable)
    }

    async fn execute(
        &self,
        method: &'static str,
        params: Value,
        limits: RpcLimits,
    ) -> Result<Value, RpcFailure> {
        if limits.timeout.is_zero()
            || limits.timeout > Duration::from_secs(60)
            || !(1..=10 * 1024 * 1024).contains(&limits.maximum_response_bytes)
        {
            return Err(RpcFailure::Protocol);
        }
        let mut cookie = read_rpc_cookie(&self.cookie_file)?;
        let request_id = self.allocate_request_id()?;
        let mut body = Zeroizing::new(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params,
            }))
            .map_err(|_| RpcFailure::Protocol)?,
        );
        if body.len() > MAX_REQUEST_BYTES {
            return Err(RpcFailure::ResponseTooLarge);
        }

        let mut authorization = BASE64.encode(&cookie);
        cookie.zeroize();
        let header = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nAuthorization: Basic {}\r\nContent-Type: application/json\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
            self.endpoint,
            authorization,
            body.len(),
        );
        authorization.zeroize();
        let mut request = Zeroizing::new(header.into_bytes());
        request.extend_from_slice(&body);
        body.zeroize();

        match time::timeout(
            limits.timeout,
            exchange(
                self.endpoint,
                &request,
                request_id,
                limits.maximum_response_bytes,
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(RpcFailure::Timeout),
        }
    }
}

impl fmt::Debug for LoopbackJsonRpc {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoopbackJsonRpc")
            .field("endpoint", &self.endpoint)
            .field("cookie_file", &"[PROTECTED]")
            .finish_non_exhaustive()
    }
}

impl BoundedRpcClient for LoopbackJsonRpc {
    fn call(&self, method: &'static str, params: Value, limits: RpcLimits) -> RpcFuture<'_> {
        Box::pin(self.execute(method, params, limits))
    }
}

async fn exchange(
    endpoint: SocketAddr,
    request: &[u8],
    request_id: u64,
    maximum_response_bytes: usize,
) -> Result<Value, RpcFailure> {
    let mut stream = TcpStream::connect(endpoint)
        .await
        .map_err(|_| RpcFailure::Unavailable)?;
    stream
        .write_all(request)
        .await
        .map_err(|_| RpcFailure::Unavailable)?;
    stream.flush().await.map_err(|_| RpcFailure::Unavailable)?;

    let body_limit = maximum_response_bytes
        .checked_add(MAX_ENVELOPE_OVERHEAD)
        .ok_or(RpcFailure::ResponseTooLarge)?;
    let (status, content_length, mut body) = read_response_head(&mut stream, body_limit).await?;
    if content_length > body_limit || body.len() > content_length {
        body.zeroize();
        return Err(RpcFailure::ResponseTooLarge);
    }
    if body.len() != content_length {
        let start = body.len();
        body.resize(content_length, 0);
        if stream.read_exact(&mut body[start..]).await.is_err() {
            body.zeroize();
            return Err(RpcFailure::Unavailable);
        }
    }

    let parsed: JsonRpcResponse = match serde_json::from_slice(&body) {
        Ok(parsed) => parsed,
        Err(_) => {
            body.zeroize();
            return Err(RpcFailure::Protocol);
        }
    };
    body.zeroize();
    if parsed.jsonrpc.as_deref() != Some("2.0") || parsed.id.as_u64() != Some(request_id) {
        return Err(RpcFailure::Protocol);
    }
    match (status, parsed.result, parsed.error) {
        (200, Some(result), None) => {
            let encoded = serde_json::to_vec(&result).map_err(|_| RpcFailure::Protocol)?;
            if encoded.len() > maximum_response_bytes {
                Err(RpcFailure::ResponseTooLarge)
            } else {
                Ok(result)
            }
        }
        (200 | 500, None, Some(error)) => Err(RpcFailure::Server(error.code)),
        _ => Err(RpcFailure::Protocol),
    }
}

async fn read_response_head(
    stream: &mut TcpStream,
    body_limit: usize,
) -> Result<(u16, usize, Vec<u8>), RpcFailure> {
    let mut response = Vec::new();
    loop {
        if let Some(boundary) = find_bytes(&response, b"\r\n\r\n") {
            let head_length = boundary + 4;
            if head_length > MAX_HEADER_BYTES {
                response.zeroize();
                return Err(RpcFailure::ResponseTooLarge);
            }
            let (status, content_length) = parse_response_head(&response[..head_length])?;
            let body = response.split_off(head_length);
            response.zeroize();
            return Ok((status, content_length, body));
        }
        if response.len() > MAX_HEADER_BYTES {
            response.zeroize();
            return Err(RpcFailure::ResponseTooLarge);
        }
        let total_limit = MAX_HEADER_BYTES
            .checked_add(body_limit)
            .ok_or(RpcFailure::ResponseTooLarge)?;
        let mut chunk = [0_u8; 8 * 1024];
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|_| RpcFailure::Unavailable)?;
        if read == 0 || response.len().saturating_add(read) > total_limit {
            response.zeroize();
            return Err(if read == 0 {
                RpcFailure::Unavailable
            } else {
                RpcFailure::ResponseTooLarge
            });
        }
        response.extend_from_slice(&chunk[..read]);
    }
}

fn parse_response_head(bytes: &[u8]) -> Result<(u16, usize), RpcFailure> {
    let text = std::str::from_utf8(bytes).map_err(|_| RpcFailure::Protocol)?;
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| {
            line.strip_prefix("HTTP/1.1 ")
                .or_else(|| line.strip_prefix("HTTP/1.0 "))
        })
        .and_then(|line| line.split_whitespace().next())
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or(RpcFailure::Protocol)?;
    let mut content_length = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(RpcFailure::Protocol)?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(RpcFailure::Protocol);
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(RpcFailure::Protocol);
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| RpcFailure::Protocol)?,
            );
        }
    }
    Ok((status, content_length.ok_or(RpcFailure::Protocol)?))
}

fn read_rpc_cookie(path: &Path) -> Result<Zeroizing<Vec<u8>>, RpcFailure> {
    let mut cookie =
        read_protected(path, MAX_COOKIE_BYTES, true).map_err(|_| RpcFailure::Unavailable)?;
    while cookie.last().is_some_and(u8::is_ascii_whitespace) {
        cookie.pop();
    }
    if cookie.len() < 3
        || cookie.len() as u64 > MAX_COOKIE_BYTES
        || cookie.contains(&b'\r')
        || cookie.contains(&b'\n')
        || cookie.first() == Some(&b':')
        || cookie.last() == Some(&b':')
        || !cookie.contains(&b':')
        || cookie.iter().any(|byte| !byte.is_ascii_graphic())
    {
        return Err(RpcFailure::Unavailable);
    }
    Ok(cookie)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|part| part == needle)
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    #[serde(default)]
    jsonrpc: Option<String>,
    id: Value,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
}

/// Invalid static live-payout authority configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum LivePayoutConfigError {
    #[error("live payout authority configuration is unsafe")]
    UnsafeRpcBoundary,
    #[error("live payout authority does not match the frozen Testnet domain")]
    AuthorityMismatch,
}

/// Chain-identity and best-chain authority backed by one local Zebra endpoint.
#[derive(Clone)]
pub(crate) struct NodePayoutAuthority {
    chain: Chain,
    rpc: Arc<dyn BoundedRpcClient>,
    expected_genesis_display: String,
    expected_branch: &'static str,
}

impl NodePayoutAuthority {
    pub(crate) fn new(
        chain: Chain,
        rpc: Arc<LoopbackJsonRpc>,
        expected_genesis_wire: [u8; 32],
    ) -> Result<Self, LivePayoutConfigError> {
        Self::with_client(chain, rpc, expected_genesis_wire)
    }

    fn with_client(
        chain: Chain,
        rpc: Arc<dyn BoundedRpcClient>,
        mut expected_genesis_wire: [u8; 32],
    ) -> Result<Self, LivePayoutConfigError> {
        if expected_genesis_wire == [0; 32] {
            return Err(LivePayoutConfigError::AuthorityMismatch);
        }
        expected_genesis_wire.reverse();
        Ok(Self {
            chain,
            rpc,
            expected_genesis_display: hex::encode(expected_genesis_wire),
            expected_branch: expected_branch(chain),
        })
    }

    pub(crate) async fn verified_tip(&self) -> Result<VerifiedTip, ObservationFailure> {
        let info = self
            .rpc
            .call("getblockchaininfo", json!([]), RpcLimits::ordinary())
            .await
            .map_err(map_observation_rpc_failure)?;
        let info: ChainInfo =
            serde_json::from_value(info).map_err(|_| ObservationFailure::Invariant)?;
        let best_tip_hash = parse_display_hash_to_wire(&info.best_block_hash)
            .filter(|hash| *hash != [0; 32])
            .ok_or(ObservationFailure::Invariant)?;
        if info.chain != "test"
            || info.blocks == 0
            || info.headers != info.blocks
            || info.consensus.chain_tip != self.expected_branch
            || info.consensus.next_block != self.expected_branch
        {
            return Err(ObservationFailure::Invariant);
        }

        let genesis = self
            .rpc
            .call("getblockhash", json!([0]), RpcLimits::compact())
            .await
            .map_err(map_observation_rpc_failure)?;
        if genesis.as_str() != Some(&self.expected_genesis_display) {
            return Err(ObservationFailure::Invariant);
        }

        let direct = self
            .rpc
            .call("getbestblockheightandhash", json!([]), RpcLimits::compact())
            .await
            .map_err(map_observation_rpc_failure)?;
        let direct: DirectTip =
            serde_json::from_value(direct).map_err(|_| ObservationFailure::Invariant)?;
        if direct.height != info.blocks || direct.hash != info.best_block_hash {
            return Err(ObservationFailure::Unavailable);
        }
        Ok(VerifiedTip {
            hash: best_tip_hash,
            height: info.blocks,
        })
    }

    /// Proves the exact historical lookup and submission RPC capabilities used
    /// by crash recovery. The malformed transaction is intentionally fixed and
    /// can never enter a mempool; `-22` proves that the node recognized
    /// `sendrawtransaction` and rejected it during consensus deserialization.
    pub(crate) async fn startup_probe(&self) -> Result<(), ObservationFailure> {
        let first_tip = self.verified_tip().await?;
        let block = self
            .rpc
            .call(
                "getblock",
                json!([self.expected_genesis_display, 1]),
                RpcLimits::ordinary(),
            )
            .await
            .map_err(map_observation_rpc_failure)?;
        let object = block.as_object().ok_or(ObservationFailure::Invariant)?;
        if object.get("hash").and_then(Value::as_str)
            != Some(self.expected_genesis_display.as_str())
            || object.get("height").and_then(Value::as_u64) != Some(0)
        {
            return Err(ObservationFailure::Invariant);
        }
        let transaction_id = object
            .get("tx")
            .and_then(Value::as_array)
            .and_then(|transactions| transactions.first())
            .and_then(Value::as_str)
            .and_then(parse_canonical_hex32)
            .filter(|transaction_id| *transaction_id != [0; 32])
            .ok_or(ObservationFailure::Invariant)?;
        if self
            .exact_raw_transaction(transaction_id)
            .await
            .map_err(map_observation_rpc_failure)?
            .is_none()
        {
            return Err(ObservationFailure::Invariant);
        }
        match self
            .rpc
            .call("sendrawtransaction", json!(["00"]), RpcLimits::compact())
            .await
        {
            Err(RpcFailure::Server(-22)) => {}
            Err(failure) => return Err(map_observation_rpc_failure(failure)),
            Ok(_) => return Err(ObservationFailure::Invariant),
        }
        if self.verified_tip().await? != first_tip {
            return Err(ObservationFailure::Unavailable);
        }
        Ok(())
    }

    async fn transaction(
        &self,
        transaction_id: [u8; 32],
    ) -> Result<ObservedTransaction, ObservationFailure> {
        let display_id = hex::encode(transaction_id);
        let response = self
            .rpc
            .call(
                "getrawtransaction",
                json!([display_id, 1]),
                RpcLimits::ordinary(),
            )
            .await;
        let value = match response {
            Ok(value) => value,
            Err(RpcFailure::Server(-5)) => return Ok(ObservedTransaction::Missing),
            Err(failure) => return Err(map_observation_rpc_failure(failure)),
        };
        parse_verbose_transaction(&value, transaction_id)
    }

    async fn block_hash(&self, height: u32) -> Result<[u8; 32], ObservationFailure> {
        let value = self
            .rpc
            .call("getblockhash", json!([height]), RpcLimits::compact())
            .await
            .map_err(map_observation_rpc_failure)?;
        value
            .as_str()
            .and_then(parse_display_hash_to_wire)
            .filter(|hash| *hash != [0; 32])
            .ok_or(ObservationFailure::Invariant)
    }

    async fn observe_watch(
        &self,
        watch: &PayoutWatch,
        tip: VerifiedTip,
        observed_at: u64,
    ) -> Result<AuthorityPayoutObservation, ObservationFailure> {
        if watch.chain != self.chain
            || watch.batch_id.is_nil()
            || watch.transaction_id == [0; 32]
            || !matches!(
                watch.state,
                PayoutBatchState::Broadcast | PayoutBatchState::Confirmed
            )
            || (watch.state == PayoutBatchState::Confirmed) != watch.prior_confirmation.is_some()
        {
            return Err(ObservationFailure::Invariant);
        }

        let transaction = self.transaction(watch.transaction_id).await?;
        let state = match transaction {
            ObservedTransaction::Mined(mut confirmation) => {
                let canonical = self.block_hash(confirmation.block_height).await?;
                if canonical != confirmation.block_hash {
                    return Err(ObservationFailure::Unavailable);
                }
                let expected_confirmations =
                    exact_confirmations(tip.height, confirmation.block_height)
                        .ok_or(ObservationFailure::Invariant)?;
                if confirmation.confirmations != expected_confirmations {
                    return Err(ObservationFailure::Unavailable);
                }
                confirmation.confirmations = expected_confirmations;
                if let Some(prior) = watch.prior_confirmation.as_ref() {
                    if prior.block_hash != confirmation.block_hash
                        || prior.block_height != confirmation.block_height
                    {
                        AuthorityPayoutState::Reorged(reorg(prior, tip, observed_at))
                    } else if confirmation.confirmations < prior.confirmations {
                        return Err(ObservationFailure::Unavailable);
                    } else {
                        AuthorityPayoutState::Mined(confirmation)
                    }
                } else {
                    AuthorityPayoutState::Mined(confirmation)
                }
            }
            ObservedTransaction::Orphan => {
                if let Some(prior) = watch.prior_confirmation.as_ref() {
                    AuthorityPayoutState::Reorged(reorg(prior, tip, observed_at))
                } else {
                    AuthorityPayoutState::Pending
                }
            }
            ObservedTransaction::Missing | ObservedTransaction::Mempool => {
                if let Some(prior) = watch.prior_confirmation.as_ref() {
                    if tip.height < prior.block_height {
                        AuthorityPayoutState::Reorged(reorg(prior, tip, observed_at))
                    } else {
                        let canonical = self.block_hash(prior.block_height).await?;
                        if canonical == prior.block_hash {
                            return Err(ObservationFailure::Invariant);
                        }
                        AuthorityPayoutState::Reorged(reorg(prior, tip, observed_at))
                    }
                } else {
                    AuthorityPayoutState::Pending
                }
            }
        };
        Ok(AuthorityPayoutObservation {
            batch_id: watch.batch_id,
            transaction_id: watch.transaction_id,
            state,
        })
    }

    /// Looks up the verbose transaction object and binds both its reported ID
    /// and exact consensus bytes to the expected signer-produced transaction.
    async fn exact_raw_transaction(
        &self,
        transaction_id: [u8; 32],
    ) -> Result<Option<Vec<u8>>, RpcFailure> {
        let response = self
            .rpc
            .call(
                "getrawtransaction",
                json!([hex::encode(transaction_id), 1]),
                RpcLimits::ordinary(),
            )
            .await;
        let value = match response {
            Ok(value) => value,
            Err(RpcFailure::Server(-5)) => return Ok(None),
            Err(failure) => return Err(failure),
        };
        let object = value.as_object().ok_or(RpcFailure::Protocol)?;
        let returned_id = object
            .get("txid")
            .and_then(Value::as_str)
            .and_then(parse_canonical_hex32)
            .ok_or(RpcFailure::Protocol)?;
        if returned_id != transaction_id {
            return Err(RpcFailure::Protocol);
        }
        let raw = object
            .get("hex")
            .and_then(Value::as_str)
            .ok_or(RpcFailure::Protocol)?;
        parse_canonical_transaction(raw)
            .map(Some)
            .ok_or(RpcFailure::Protocol)
    }
}

impl PayoutConfirmationAuthority for NodePayoutAuthority {
    fn chain(&self) -> Chain {
        self.chain
    }

    fn snapshot(&self, watches: &[PayoutWatch]) -> ObservationFuture<'_, AuthoritySnapshot> {
        let watches = watches.to_vec();
        Box::pin(async move {
            let mut ids = HashSet::with_capacity(watches.len());
            if watches
                .iter()
                .any(|watch| !ids.insert(watch.transaction_id))
            {
                return Err(ObservationFailure::Invariant);
            }
            let first_tip = self.verified_tip().await?;
            let observed_at = unix_time()?;
            let mut payouts = Vec::with_capacity(watches.len());
            for watch in &watches {
                payouts.push(self.observe_watch(watch, first_tip, observed_at).await?);
            }
            let second_tip = self.verified_tip().await?;
            if second_tip != first_tip {
                return Err(ObservationFailure::Unavailable);
            }
            Ok(AuthoritySnapshot {
                chain: self.chain,
                best_tip_hash: first_tip.hash,
                best_tip_height: first_tip.height,
                observed_at,
                payouts,
            })
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedTip {
    pub(crate) hash: [u8; 32],
    pub(crate) height: u32,
}

#[derive(Deserialize)]
struct ChainInfo {
    chain: String,
    blocks: u32,
    headers: u32,
    #[serde(rename = "bestblockhash")]
    best_block_hash: String,
    consensus: ConsensusBranches,
}

#[derive(Deserialize)]
struct ConsensusBranches {
    #[serde(rename = "chaintip")]
    chain_tip: String,
    #[serde(rename = "nextblock")]
    next_block: String,
}

#[derive(Deserialize)]
struct DirectTip {
    height: u32,
    hash: String,
}

enum ObservedTransaction {
    Missing,
    Mempool,
    Orphan,
    Mined(PayoutConfirmation),
}

fn parse_verbose_transaction(
    value: &Value,
    expected_transaction_id: [u8; 32],
) -> Result<ObservedTransaction, ObservationFailure> {
    let object = value.as_object().ok_or(ObservationFailure::Invariant)?;
    let transaction_id = object
        .get("txid")
        .and_then(Value::as_str)
        .and_then(parse_canonical_hex32)
        .ok_or(ObservationFailure::Invariant)?;
    let raw = object
        .get("hex")
        .and_then(Value::as_str)
        .and_then(parse_canonical_transaction)
        .ok_or(ObservationFailure::Invariant)?;
    if transaction_id != expected_transaction_id || raw.is_empty() {
        return Err(ObservationFailure::Invariant);
    }
    let in_active_chain = object
        .get("in_active_chain")
        .map(|value| value.as_bool().ok_or(ObservationFailure::Invariant))
        .transpose()?;

    let height = object.get("height");
    let confirmations = object.get("confirmations");
    let block_hash = object.get("blockhash");
    match (height, confirmations, block_hash) {
        (None, None, None) => {
            if in_active_chain == Some(true) {
                return Err(ObservationFailure::Invariant);
            }
            Ok(ObservedTransaction::Mempool)
        }
        (Some(height), Some(confirmations), Some(block_hash)) => {
            if in_active_chain == Some(false) {
                let valid_orphan = height.as_i64() == Some(-1)
                    && confirmations.as_u64() == Some(0)
                    && block_hash
                        .as_str()
                        .and_then(parse_display_hash_to_wire)
                        .is_some_and(|hash| hash != [0; 32]);
                return if valid_orphan {
                    Ok(ObservedTransaction::Orphan)
                } else {
                    Err(ObservationFailure::Invariant)
                };
            }
            let height = height
                .as_u64()
                .and_then(|height| u32::try_from(height).ok())
                .filter(|height| *height > 0)
                .ok_or(ObservationFailure::Invariant)?;
            let confirmations = confirmations
                .as_u64()
                .and_then(|count| u32::try_from(count).ok())
                .filter(|count| *count > 0)
                .ok_or(ObservationFailure::Invariant)?;
            let block_hash = block_hash
                .as_str()
                .and_then(parse_display_hash_to_wire)
                .filter(|hash| *hash != [0; 32])
                .ok_or(ObservationFailure::Invariant)?;
            Ok(ObservedTransaction::Mined(PayoutConfirmation {
                block_hash,
                block_height: height,
                confirmations,
            }))
        }
        _ => Err(ObservationFailure::Invariant),
    }
}

fn reorg(prior: &PayoutConfirmation, tip: VerifiedTip, observed_at: u64) -> PayoutReorg {
    PayoutReorg {
        prior_confirmation: prior.clone(),
        replacement_tip_hash: tip.hash,
        replacement_tip_height: tip.height,
        observed_at,
    }
}

fn exact_confirmations(tip_height: u32, block_height: u32) -> Option<u32> {
    tip_height
        .checked_sub(block_height)
        .and_then(|depth| depth.checked_add(1))
}

fn expected_branch(chain: Chain) -> &'static str {
    match chain {
        Chain::Wcash => WCASH_TESTNET_BRANCH_ID,
        Chain::Zcash => ZCASH_NU6_3_BRANCH_ID,
    }
}

fn map_observation_rpc_failure(failure: RpcFailure) -> ObservationFailure {
    match failure {
        RpcFailure::Timeout | RpcFailure::Unavailable | RpcFailure::Server(-28) => {
            ObservationFailure::Unavailable
        }
        RpcFailure::ResponseTooLarge | RpcFailure::Protocol | RpcFailure::Server(_) => {
            ObservationFailure::Invariant
        }
    }
}

/// Exact-byte transaction broadcaster backed by the same independently
/// authenticated validator used for confirmation decisions.
///
/// A successful `sendrawtransaction` response and every server-side
/// already-known/rejection response remain ambiguous until a subsequent
/// verbose lookup returns the expected transaction ID and byte-for-byte
/// signer-produced serialization.
pub(crate) struct RpcExactBroadcaster {
    authority: Arc<NodePayoutAuthority>,
}

impl RpcExactBroadcaster {
    pub(crate) fn new(authority: Arc<NodePayoutAuthority>) -> Self {
        Self { authority }
    }

    async fn submit(&self, artifact: &SignedPayoutArtifact) -> Result<(), BoundaryFailure> {
        if artifact.chain != self.authority.chain
            || artifact.state != PayoutBatchState::Signed
            || artifact.batch_id.is_nil()
            || artifact.transaction_id == [0; 32]
            || artifact.unsigned_digest == [0; 32]
            || artifact.signed_transaction.is_empty()
            || artifact.signed_transaction.len() > MAX_TRANSACTION_BYTES
        {
            return Err(BoundaryFailure::Invariant);
        }

        let first_tip = self
            .authority
            .verified_tip()
            .await
            .map_err(map_boundary_observation_failure)?;
        match self
            .authority
            .exact_raw_transaction(artifact.transaction_id)
            .await
        {
            Ok(Some(raw)) if raw == artifact.signed_transaction => {
                let second_tip = self
                    .authority
                    .verified_tip()
                    .await
                    .map_err(map_boundary_observation_failure)?;
                return if second_tip == first_tip {
                    Ok(())
                } else {
                    Err(BoundaryFailure::Retryable)
                };
            }
            Ok(Some(_)) => return Err(BoundaryFailure::Invariant),
            Ok(None) => {}
            Err(failure) => return Err(map_prebroadcast_failure(failure)),
        }

        let raw_hex = hex::encode(&artifact.signed_transaction);
        let expected_id = hex::encode(artifact.transaction_id);
        let submission = self
            .authority
            .rpc
            .call(
                "sendrawtransaction",
                json!([raw_hex]),
                RpcLimits::ordinary(),
            )
            .await;
        let disposition = match submission {
            Ok(value) if value.as_str() == Some(&expected_id) => SubmissionDisposition::Accepted,
            Ok(_) => return Err(BoundaryFailure::Invariant),
            Err(RpcFailure::Server(code)) => SubmissionDisposition::Server(code),
            Err(RpcFailure::Timeout | RpcFailure::Unavailable) => SubmissionDisposition::Ambiguous,
            Err(RpcFailure::ResponseTooLarge | RpcFailure::Protocol) => {
                return Err(BoundaryFailure::Invariant);
            }
        };

        let exact_lookup = self
            .authority
            .exact_raw_transaction(artifact.transaction_id)
            .await;
        let exact =
            matches!(exact_lookup, Ok(Some(ref raw)) if *raw == artifact.signed_transaction);
        if exact {
            let second_tip = self
                .authority
                .verified_tip()
                .await
                .map_err(map_boundary_observation_failure)?;
            return if second_tip == first_tip {
                Ok(())
            } else {
                Err(BoundaryFailure::Retryable)
            };
        }
        if matches!(exact_lookup, Ok(Some(_))) {
            return Err(BoundaryFailure::Invariant);
        }
        match disposition {
            SubmissionDisposition::Server(-22 | -25 | -26) => Err(BoundaryFailure::Rejected),
            SubmissionDisposition::Accepted
            | SubmissionDisposition::Server(_)
            | SubmissionDisposition::Ambiguous => Err(BoundaryFailure::Ambiguous),
        }
    }
}

impl ExactTransactionBroadcaster for RpcExactBroadcaster {
    fn chain(&self) -> Chain {
        self.authority.chain
    }

    fn rebroadcast_exact(&self, artifact: &SignedPayoutArtifact) -> BoundaryFuture<'_, ()> {
        let artifact = artifact.clone();
        Box::pin(async move { self.submit(&artifact).await })
    }
}

enum SubmissionDisposition {
    Accepted,
    Server(i64),
    Ambiguous,
}

fn map_prebroadcast_failure(failure: RpcFailure) -> BoundaryFailure {
    match failure {
        RpcFailure::Timeout | RpcFailure::Unavailable | RpcFailure::Server(-28) => {
            BoundaryFailure::Retryable
        }
        RpcFailure::ResponseTooLarge | RpcFailure::Protocol | RpcFailure::Server(_) => {
            BoundaryFailure::Invariant
        }
    }
}

fn map_boundary_observation_failure(failure: ObservationFailure) -> BoundaryFailure {
    match failure {
        ObservationFailure::Unavailable => BoundaryFailure::Retryable,
        ObservationFailure::Invariant => BoundaryFailure::Invariant,
    }
}

/// Seedless, synchronized Zallet observation restricted to one Ironwood-only
/// collector account.
pub(crate) struct ZalletObservationSource {
    rpc: Arc<dyn BoundedRpcClient>,
    account_id: Uuid,
    account_index: u32,
    minimum_confirmations: u32,
    expected_payout_commitment: [u8; 32],
}

impl ZalletObservationSource {
    pub(crate) fn new(
        rpc: Arc<LoopbackJsonRpc>,
        account_id: Uuid,
        account_index: u32,
        minimum_confirmations: u32,
        expected_payout_commitment: [u8; 32],
    ) -> Result<Self, LivePayoutConfigError> {
        Self::with_client(
            rpc,
            account_id,
            account_index,
            minimum_confirmations,
            expected_payout_commitment,
        )
    }

    fn with_client(
        rpc: Arc<dyn BoundedRpcClient>,
        account_id: Uuid,
        account_index: u32,
        minimum_confirmations: u32,
        expected_payout_commitment: [u8; 32],
    ) -> Result<Self, LivePayoutConfigError> {
        if account_id.is_nil()
            || account_index >= (1 << 31)
            || !(100..=1_000_000).contains(&minimum_confirmations)
            || expected_payout_commitment == [0; 32]
        {
            return Err(LivePayoutConfigError::AuthorityMismatch);
        }
        Ok(Self {
            rpc,
            account_id,
            account_index,
            minimum_confirmations,
            expected_payout_commitment,
        })
    }

    async fn observe_inner(&self) -> Result<WalletObservation, ObservationFailure> {
        let first_status = self.status().await?;
        let seed_fingerprint = self.account_identity().await?;
        self.collector_commitment(seed_fingerprint).await?;
        let spendable = self.ironwood_balance().await?;
        let second_status = self.status().await?;
        if first_status != second_status {
            return Err(ObservationFailure::Unavailable);
        }
        let tip = first_status.ready_tip()?;
        let observed_at = unix_time()?;
        let valid_until = observed_at
            .checked_add(OBSERVATION_VALIDITY_SECS)
            .ok_or(ObservationFailure::Invariant)?;
        let mut digest = Sha256::new();
        digest.update(WALLET_OBSERVATION_DOMAIN);
        digest.update(self.account_id.as_bytes());
        digest.update(self.account_index.to_be_bytes());
        digest.update(seed_fingerprint);
        digest.update(self.expected_payout_commitment);
        digest.update(self.minimum_confirmations.to_be_bytes());
        digest.update(spendable.to_be_bytes());
        digest.update(tip.hash);
        digest.update(tip.height.to_be_bytes());
        let wallet_state_digest: [u8; 32] = digest.finalize().into();
        Ok(WalletObservation {
            chain: Chain::Zcash,
            wallet_state_digest,
            wallet_spendable_zat: spendable,
            best_tip_hash: tip.hash,
            best_tip_height: tip.height,
            observed_at,
            valid_until,
        })
    }

    /// Proves that a newly provisioned, dedicated Zallet collector has no
    /// mature, locked, pending, or dust value before it is bound to this pool.
    ///
    /// The ordinary observer intentionally does not impose this one-time gate:
    /// after mining starts, pending coinbase rewards are expected.
    pub(crate) async fn verify_fresh_zero(&self) -> Result<WalletObservation, ObservationFailure> {
        let observation = self.observe_inner().await?;
        let first_status = self.status().await?;
        let value = self
            .rpc
            .call("z_getbalances", json!([0]), RpcLimits::ordinary())
            .await
            .map_err(map_observation_rpc_failure)?;
        parse_fresh_zero_balances(&value, self.account_id)?;
        let second_status = self.status().await?;
        if first_status != second_status {
            return Err(ObservationFailure::Unavailable);
        }
        let tip = first_status.ready_tip()?;
        if tip.hash != observation.best_tip_hash || tip.height != observation.best_tip_height {
            return Err(ObservationFailure::Unavailable);
        }
        Ok(observation)
    }

    async fn status(&self) -> Result<ZalletStatus, ObservationFailure> {
        let value = self
            .rpc
            .call("getwalletstatus", json!([]), RpcLimits::compact())
            .await
            .map_err(map_observation_rpc_failure)?;
        serde_json::from_value(value).map_err(|_| ObservationFailure::Invariant)
    }

    async fn account_identity(&self) -> Result<[u8; 32], ObservationFailure> {
        let value = self
            .rpc
            .call("z_listaccounts", json!([false]), RpcLimits::ordinary())
            .await
            .map_err(map_observation_rpc_failure)?;
        let accounts: Vec<ListedAccount> =
            serde_json::from_value(value).map_err(|_| ObservationFailure::Invariant)?;
        let mut matched = None;
        for account in accounts {
            let parsed = Uuid::parse_str(&account.account_uuid)
                .ok()
                .filter(|uuid| !uuid.is_nil() && uuid.to_string() == account.account_uuid)
                .ok_or(ObservationFailure::Invariant)?;
            if account.addresses_present {
                return Err(ObservationFailure::Invariant);
            }
            if parsed != self.account_id {
                continue;
            }
            if matched.is_some()
                || account.zip32_account_index != Some(self.account_index)
                || account
                    .legacy_account_index
                    .is_some_and(|index| index != self.account_index)
            {
                return Err(ObservationFailure::Invariant);
            }
            let fingerprint = account
                .seed_fingerprint
                .as_deref()
                .and_then(|encoded| {
                    encoded
                        .parse::<SeedFingerprint>()
                        .ok()
                        .filter(|fingerprint| fingerprint.to_string() == encoded)
                })
                .map(|fingerprint| fingerprint.to_bytes())
                .filter(|fingerprint| *fingerprint != [0; 32])
                .ok_or(ObservationFailure::Invariant)?;
            matched = Some(fingerprint);
        }
        matched.ok_or(ObservationFailure::Invariant)
    }

    async fn ironwood_balance(&self) -> Result<u64, ObservationFailure> {
        let value = self
            .rpc
            .call(
                "z_getbalanceforaccount",
                json!([self.account_id.to_string(), self.minimum_confirmations]),
                RpcLimits::ordinary(),
            )
            .await
            .map_err(map_observation_rpc_failure)?;
        parse_ironwood_balance(&value, self.minimum_confirmations)
    }

    async fn collector_commitment(
        &self,
        expected_seed_fingerprint: [u8; 32],
    ) -> Result<(), ObservationFailure> {
        let value = self
            .rpc
            .call(
                "z_getaccount",
                json!([self.account_id.to_string()]),
                RpcLimits::ordinary(),
            )
            .await
            .map_err(map_observation_rpc_failure)?;
        let account: DetailedAccount =
            serde_json::from_value(value).map_err(|_| ObservationFailure::Invariant)?;
        account.verify(
            self.account_id,
            self.account_index,
            expected_seed_fingerprint,
            self.expected_payout_commitment,
        )
    }
}

impl WalletObservationSource for ZalletObservationSource {
    fn chain(&self) -> Chain {
        Chain::Zcash
    }

    fn observe(&self) -> ObservationFuture<'_, WalletObservation> {
        Box::pin(self.observe_inner())
    }
}

#[derive(Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ZalletStatus {
    node_tip: ZalletTip,
    #[serde(default, deserialize_with = "present_non_null")]
    wallet_tip: Option<ZalletTip>,
    #[serde(default, deserialize_with = "present_non_null")]
    fully_synced_height: Option<u32>,
    #[serde(
        default,
        rename = "sync_work_remaining",
        deserialize_with = "field_is_present"
    )]
    sync_work_remaining_present: bool,
    locked: bool,
}

impl ZalletStatus {
    fn ready_tip(&self) -> Result<VerifiedTip, ObservationFailure> {
        let wallet_tip = self
            .wallet_tip
            .as_ref()
            .ok_or(ObservationFailure::Unavailable)?;
        let hash = parse_display_hash_to_wire(&self.node_tip.blockhash)
            .filter(|hash| *hash != [0; 32])
            .ok_or(ObservationFailure::Invariant)?;
        if self.locked
            || self.sync_work_remaining_present
            || self.node_tip != *wallet_tip
            || self.node_tip.height == 0
            || self.fully_synced_height != Some(self.node_tip.height)
        {
            return Err(ObservationFailure::Unavailable);
        }
        Ok(VerifiedTip {
            hash,
            height: self.node_tip.height,
        })
    }
}

#[derive(Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ZalletTip {
    blockhash: String,
    height: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListedAccount {
    account_uuid: String,
    #[serde(default, rename = "name", deserialize_with = "present_non_null")]
    _name: Option<String>,
    #[serde(default, rename = "seedfp", deserialize_with = "present_non_null")]
    seed_fingerprint: Option<String>,
    #[serde(default, deserialize_with = "present_non_null")]
    zip32_account_index: Option<u32>,
    #[serde(default, rename = "account", deserialize_with = "present_non_null")]
    legacy_account_index: Option<u32>,
    #[serde(default, rename = "addresses", deserialize_with = "field_is_present")]
    addresses_present: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DetailedAccount {
    account_uuid: String,
    #[serde(default, rename = "name", deserialize_with = "present_non_null")]
    _name: Option<String>,
    #[serde(default, rename = "seedfp", deserialize_with = "present_non_null")]
    seed_fingerprint: Option<String>,
    #[serde(default, deserialize_with = "present_non_null")]
    zip32_account_index: Option<u32>,
    addresses: Vec<DetailedAddress>,
}

impl DetailedAccount {
    fn verify(
        self,
        expected_account: Uuid,
        expected_index: u32,
        expected_seed_fingerprint: [u8; 32],
        expected_commitment: [u8; 32],
    ) -> Result<(), ObservationFailure> {
        let account_id = Uuid::parse_str(&self.account_uuid)
            .ok()
            .filter(|uuid| !uuid.is_nil() && uuid.to_string() == self.account_uuid)
            .ok_or(ObservationFailure::Invariant)?;
        let fingerprint = self
            .seed_fingerprint
            .as_deref()
            .and_then(|encoded| {
                encoded
                    .parse::<SeedFingerprint>()
                    .ok()
                    .filter(|fingerprint| fingerprint.to_string() == encoded)
            })
            .map(|fingerprint| fingerprint.to_bytes())
            .ok_or(ObservationFailure::Invariant)?;
        if account_id != expected_account
            || self.zip32_account_index != Some(expected_index)
            || fingerprint != expected_seed_fingerprint
        {
            return Err(ObservationFailure::Invariant);
        }

        let mut matching = self.addresses.iter().filter_map(|address| {
            address.ua.as_deref().and_then(|candidate| {
                validated_parent_payout_address_commitment(candidate)
                    .ok()
                    .filter(|commitment| *commitment == expected_commitment)
            })
        });
        if matching.next() != Some(expected_commitment) || matching.next().is_some() {
            return Err(ObservationFailure::Invariant);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DetailedAddress {
    #[serde(
        default,
        rename = "diversifier_index",
        deserialize_with = "present_non_null"
    )]
    _diversifier_index: Option<u128>,
    #[serde(default, deserialize_with = "present_non_null")]
    ua: Option<String>,
    #[serde(default, rename = "sapling", deserialize_with = "present_non_null")]
    _sapling: Option<String>,
    #[serde(default, rename = "transparent", deserialize_with = "present_non_null")]
    _transparent: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolBalance {
    #[serde(rename = "valueZat")]
    value_zat: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FreshBalances {
    accounts: Vec<FreshAccountBalance>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FreshAccountBalance {
    account_uuid: String,
    total: FreshTotalBalance,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FreshTotalBalance {
    spendable: PoolBalance,
}

fn parse_fresh_zero_balances(
    value: &Value,
    expected_account: Uuid,
) -> Result<(), ObservationFailure> {
    let balances: FreshBalances =
        serde_json::from_value(value.clone()).map_err(|_| ObservationFailure::Invariant)?;
    let [account] = balances.accounts.as_slice() else {
        return Err(ObservationFailure::Invariant);
    };
    let account_id = Uuid::parse_str(&account.account_uuid)
        .ok()
        .filter(|uuid| !uuid.is_nil() && uuid.to_string() == account.account_uuid)
        .ok_or(ObservationFailure::Invariant)?;
    if account_id != expected_account || account.total.spendable.value_zat != 0 {
        return Err(ObservationFailure::Invariant);
    }
    Ok(())
}

fn parse_ironwood_balance(
    value: &Value,
    expected_confirmations: u32,
) -> Result<u64, ObservationFailure> {
    let object = value.as_object().ok_or(ObservationFailure::Invariant)?;
    if object.len() != 2
        || object.get("minimum_confirmations").and_then(Value::as_u64)
            != Some(u64::from(expected_confirmations))
    {
        return Err(ObservationFailure::Invariant);
    }
    let pools = object
        .get("pools")
        .and_then(Value::as_object)
        .ok_or(ObservationFailure::Invariant)?;
    if pools.keys().any(|name| {
        !matches!(
            name.as_str(),
            "transparent" | "sapling" | "orchard" | "ironwood"
        )
    }) || pools.contains_key("transparent")
        || pools.contains_key("sapling")
        || pools.contains_key("orchard")
    {
        return Err(ObservationFailure::Invariant);
    }
    let Some(ironwood) = pools.get("ironwood") else {
        return Ok(0);
    };
    let balance: PoolBalance =
        serde_json::from_value(ironwood.clone()).map_err(|_| ObservationFailure::Invariant)?;
    if balance.value_zat == 0 {
        return Err(ObservationFailure::Invariant);
    }
    Ok(balance.value_zat)
}

fn field_is_present<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    serde::de::IgnoredAny::deserialize(deserializer)?;
    Ok(true)
}

fn present_non_null<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn unix_time() -> Result<u64, ObservationFailure> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
        .filter(|seconds| *seconds > 0)
        .ok_or(ObservationFailure::Unavailable)
}

fn parse_canonical_hex32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    hex::decode(value).ok()?.try_into().ok()
}

// Zebra and Zallet render block hashes in conventional display order, while
// pool persistence and Wolf payout observations use backend wire order.
// Transaction IDs are deliberately excluded: both payout signers persist their
// canonical display strings decoded byte-for-byte for exact RPC round trips.
fn parse_display_hash_to_wire(value: &str) -> Option<[u8; 32]> {
    let mut hash = parse_canonical_hex32(value)?;
    hash.reverse();
    Some(hash)
}

fn parse_canonical_transaction(value: &str) -> Option<Vec<u8>> {
    if value.is_empty()
        || value.len() > MAX_TRANSACTION_BYTES.checked_mul(2)?
        || !value.len().is_multiple_of(2)
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    hex::decode(value).ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use std::{
        collections::VecDeque,
        fs::{self, OpenOptions},
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
        sync::Mutex,
    };

    use serde_json::{json, Map};
    use tempfile::Builder as TempDirBuilder;
    use tokio::{io::AsyncReadExt, net::TcpListener};

    use super::*;

    const GENESIS: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const TIP: [u8; 32] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
        0x3e, 0x3f,
    ];
    const BLOCK: [u8; 32] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
        0x5e, 0x5f,
    ];
    const TRANSACTION: [u8; 32] = [
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
        0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d,
        0x7e, 0x7f,
    ];
    const ACCOUNT: Uuid = Uuid::from_u128(0xaaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaaaa);
    const ZEC_COLLECTOR: &str = "utest10zg6frxk32ma8980kdv9473e4aclw7clq9hydzcj6l349pkqzxk2mmj3cn7j5x38w6l4wyryv50whnlrw0k9agzpdf5fxyj7kq96ukcp";

    struct RpcStep {
        method: &'static str,
        params: Value,
        result: Result<Value, RpcFailure>,
    }

    struct ScriptedRpc {
        steps: Mutex<VecDeque<RpcStep>>,
    }

    impl ScriptedRpc {
        fn new(steps: Vec<RpcStep>) -> Self {
            Self {
                steps: Mutex::new(steps.into()),
            }
        }

        fn assert_drained(&self) {
            assert!(self.steps.lock().expect("test mutex").is_empty());
        }
    }

    impl BoundedRpcClient for ScriptedRpc {
        fn call(&self, method: &'static str, params: Value, limits: RpcLimits) -> RpcFuture<'_> {
            assert!(!limits.timeout.is_zero());
            assert!(limits.maximum_response_bytes > 0);
            let step = self
                .steps
                .lock()
                .expect("test mutex")
                .pop_front()
                .unwrap_or_else(|| panic!("unexpected RPC call: {method}"));
            assert_eq!(step.method, method);
            assert_eq!(step.params, params);
            Box::pin(async move { step.result })
        }
    }

    fn ok(method: &'static str, params: Value, result: Value) -> RpcStep {
        RpcStep {
            method,
            params,
            result: Ok(result),
        }
    }

    fn failure(method: &'static str, params: Value, result: RpcFailure) -> RpcStep {
        RpcStep {
            method,
            params,
            result: Err(result),
        }
    }

    fn display_hash(mut wire_hash: [u8; 32]) -> String {
        wire_hash.reverse();
        hex::encode(wire_hash)
    }

    fn push_tip(steps: &mut Vec<RpcStep>, branch: &str, tip: [u8; 32], height: u32) {
        steps.push(ok(
            "getblockchaininfo",
            json!([]),
            json!({
                "chain": "test",
                "blocks": height,
                "headers": height,
                "bestblockhash": display_hash(tip),
                "consensus": { "chaintip": branch, "nextblock": branch },
            }),
        ));
        steps.push(ok("getblockhash", json!([0]), json!(display_hash(GENESIS))));
        steps.push(ok(
            "getbestblockheightandhash",
            json!([]),
            json!({ "height": height, "hash": display_hash(tip) }),
        ));
    }

    fn authority(chain: Chain, rpc: Arc<ScriptedRpc>) -> NodePayoutAuthority {
        NodePayoutAuthority::with_client(chain, rpc, GENESIS).expect("valid authority")
    }

    fn watch() -> PayoutWatch {
        PayoutWatch {
            batch_id: Uuid::from_u128(0xbbbbbbbb_bbbb_4bbb_8bbb_bbbbbbbbbbbb),
            chain: Chain::Wcash,
            state: PayoutBatchState::Broadcast,
            transaction_id: TRANSACTION,
            prior_confirmation: None,
        }
    }

    fn signed_artifact() -> SignedPayoutArtifact {
        SignedPayoutArtifact {
            batch_id: Uuid::from_u128(0xbbbbbbbb_bbbb_4bbb_8bbb_bbbbbbbbbbbb),
            chain: Chain::Wcash,
            state: PayoutBatchState::Signed,
            unsigned_digest: [0x55; 32],
            transaction_id: TRANSACTION,
            signed_transaction: vec![0x01, 0x02],
            network_fee_zat: 10_000,
        }
    }

    #[test]
    fn block_hashes_reverse_to_wire_order_but_transaction_ids_do_not() {
        assert_eq!(parse_display_hash_to_wire(&display_hash(TIP)), Some(TIP));
        assert_eq!(
            parse_canonical_hex32(&hex::encode(TRANSACTION)),
            Some(TRANSACTION)
        );
        assert_ne!(hex::encode(TRANSACTION), display_hash(TRANSACTION));
    }

    #[tokio::test]
    async fn validator_observes_one_stable_canonical_confirmation() {
        let mut steps = Vec::new();
        push_tip(&mut steps, WCASH_TESTNET_BRANCH_ID, TIP, 100);
        steps.push(ok(
            "getrawtransaction",
            json!([hex::encode(TRANSACTION), 1]),
            json!({
                "txid": hex::encode(TRANSACTION),
                "hex": "0102",
                "height": 98,
                "confirmations": 3,
                "blockhash": display_hash(BLOCK),
                "in_active_chain": true,
            }),
        ));
        steps.push(ok("getblockhash", json!([98]), json!(display_hash(BLOCK))));
        push_tip(&mut steps, WCASH_TESTNET_BRANCH_ID, TIP, 100);
        let rpc = Arc::new(ScriptedRpc::new(steps));
        let snapshot = authority(Chain::Wcash, Arc::clone(&rpc))
            .snapshot(&[watch()])
            .await
            .expect("stable authority snapshot");

        assert_eq!(snapshot.chain, Chain::Wcash);
        assert_eq!(snapshot.best_tip_hash, TIP);
        assert_eq!(snapshot.best_tip_height, 100);
        assert_eq!(snapshot.payouts.len(), 1);
        assert!(matches!(
            &snapshot.payouts[0].state,
            AuthorityPayoutState::Mined(PayoutConfirmation {
                block_hash: BLOCK,
                block_height: 98,
                confirmations: 3,
            })
        ));
        rpc.assert_drained();
    }

    #[tokio::test]
    async fn validator_treats_zebra_mempool_false_as_pending() {
        let mut steps = Vec::new();
        push_tip(&mut steps, WCASH_TESTNET_BRANCH_ID, TIP, 100);
        steps.push(ok(
            "getrawtransaction",
            json!([hex::encode(TRANSACTION), 1]),
            json!({
                "txid": hex::encode(TRANSACTION),
                "hex": "0102",
                "in_active_chain": false,
            }),
        ));
        push_tip(&mut steps, WCASH_TESTNET_BRANCH_ID, TIP, 100);
        let rpc = Arc::new(ScriptedRpc::new(steps));
        let snapshot = authority(Chain::Wcash, Arc::clone(&rpc))
            .snapshot(&[watch()])
            .await
            .expect("Zebra mempool shape is valid");
        assert!(matches!(
            snapshot.payouts[0].state,
            AuthorityPayoutState::Pending
        ));
        rpc.assert_drained();
    }

    #[tokio::test]
    async fn validator_models_zebra_orphan_as_pending_or_persistable_reorg() {
        let orphan = json!({
            "txid": hex::encode(TRANSACTION),
            "hex": "0102",
            "height": -1,
            "confirmations": 0,
            "blockhash": display_hash(BLOCK),
            "in_active_chain": false,
        });

        let mut pending_steps = Vec::new();
        push_tip(&mut pending_steps, WCASH_TESTNET_BRANCH_ID, TIP, 100);
        pending_steps.push(ok(
            "getrawtransaction",
            json!([hex::encode(TRANSACTION), 1]),
            orphan.clone(),
        ));
        push_tip(&mut pending_steps, WCASH_TESTNET_BRANCH_ID, TIP, 100);
        let pending_rpc = Arc::new(ScriptedRpc::new(pending_steps));
        let pending = authority(Chain::Wcash, Arc::clone(&pending_rpc))
            .snapshot(&[watch()])
            .await
            .expect("orphan remains pending before first confirmation");
        assert!(matches!(
            pending.payouts[0].state,
            AuthorityPayoutState::Pending
        ));
        pending_rpc.assert_drained();

        let prior = PayoutConfirmation {
            block_hash: [0x73; 32],
            block_height: 97,
            confirmations: 4,
        };
        let mut confirmed_watch = watch();
        confirmed_watch.state = PayoutBatchState::Confirmed;
        confirmed_watch.prior_confirmation = Some(prior.clone());
        let mut reorg_steps = Vec::new();
        push_tip(&mut reorg_steps, WCASH_TESTNET_BRANCH_ID, TIP, 100);
        reorg_steps.push(ok(
            "getrawtransaction",
            json!([hex::encode(TRANSACTION), 1]),
            orphan,
        ));
        push_tip(&mut reorg_steps, WCASH_TESTNET_BRANCH_ID, TIP, 100);
        let reorg_rpc = Arc::new(ScriptedRpc::new(reorg_steps));
        let reorged = authority(Chain::Wcash, Arc::clone(&reorg_rpc))
            .snapshot(&[confirmed_watch])
            .await
            .expect("orphan produces durable reorg facts");
        assert!(matches!(
            &reorged.payouts[0].state,
            AuthorityPayoutState::Reorged(PayoutReorg {
                prior_confirmation,
                replacement_tip_hash: TIP,
                replacement_tip_height: 100,
                ..
            }) if prior_confirmation == &prior
        ));
        reorg_rpc.assert_drained();
    }

    #[test]
    fn verbose_transaction_rejects_contradictory_active_chain_facts() {
        let positive_but_inactive = json!({
            "txid": hex::encode(TRANSACTION),
            "hex": "0102",
            "height": 98,
            "confirmations": 3,
            "blockhash": display_hash(BLOCK),
            "in_active_chain": false,
        });
        assert!(matches!(
            parse_verbose_transaction(&positive_but_inactive, TRANSACTION),
            Err(ObservationFailure::Invariant)
        ));
        let active_but_unmined = json!({
            "txid": hex::encode(TRANSACTION),
            "hex": "0102",
            "in_active_chain": true,
        });
        assert!(matches!(
            parse_verbose_transaction(&active_but_unmined, TRANSACTION),
            Err(ObservationFailure::Invariant)
        ));
    }

    #[tokio::test]
    async fn startup_probe_requires_historical_verbose_lookup_and_submit_capability() {
        let genesis_transaction = [0x66; 32];
        let mut steps = Vec::new();
        push_tip(&mut steps, WCASH_TESTNET_BRANCH_ID, TIP, 100);
        steps.push(ok(
            "getblock",
            json!([display_hash(GENESIS), 1]),
            json!({
                "hash": display_hash(GENESIS),
                "height": 0,
                "tx": [hex::encode(genesis_transaction)],
            }),
        ));
        steps.push(ok(
            "getrawtransaction",
            json!([hex::encode(genesis_transaction), 1]),
            json!({
                "txid": hex::encode(genesis_transaction),
                "hex": "0102",
            }),
        ));
        steps.push(failure(
            "sendrawtransaction",
            json!(["00"]),
            RpcFailure::Server(-22),
        ));
        push_tip(&mut steps, WCASH_TESTNET_BRANCH_ID, TIP, 100);
        let rpc = Arc::new(ScriptedRpc::new(steps));

        authority(Chain::Wcash, Arc::clone(&rpc))
            .startup_probe()
            .await
            .expect("all recovery RPCs proved");
        rpc.assert_drained();

        let mut missing_index = Vec::new();
        push_tip(&mut missing_index, WCASH_TESTNET_BRANCH_ID, TIP, 100);
        missing_index.push(ok(
            "getblock",
            json!([display_hash(GENESIS), 1]),
            json!({
                "hash": display_hash(GENESIS),
                "height": 0,
                "tx": [hex::encode(genesis_transaction)],
            }),
        ));
        missing_index.push(failure(
            "getrawtransaction",
            json!([hex::encode(genesis_transaction), 1]),
            RpcFailure::Server(-5),
        ));
        let rpc = Arc::new(ScriptedRpc::new(missing_index));
        assert_eq!(
            authority(Chain::Wcash, Arc::clone(&rpc))
                .startup_probe()
                .await,
            Err(ObservationFailure::Invariant)
        );
        rpc.assert_drained();
    }

    #[tokio::test]
    async fn validator_rejects_branch_mismatch_and_confirmation_tip_race() {
        let branch_rpc = Arc::new(ScriptedRpc::new(vec![ok(
            "getblockchaininfo",
            json!([]),
            json!({
                "chain": "test",
                "blocks": 100,
                "headers": 100,
                "bestblockhash": display_hash(TIP),
                "consensus": { "chaintip": ZCASH_NU6_3_BRANCH_ID, "nextblock": ZCASH_NU6_3_BRANCH_ID },
            }),
        )]));
        assert_eq!(
            authority(Chain::Wcash, Arc::clone(&branch_rpc))
                .snapshot(&[])
                .await,
            Err(ObservationFailure::Invariant)
        );
        branch_rpc.assert_drained();

        let mut steps = Vec::new();
        push_tip(&mut steps, WCASH_TESTNET_BRANCH_ID, TIP, 100);
        steps.push(ok(
            "getrawtransaction",
            json!([hex::encode(TRANSACTION), 1]),
            json!({
                "txid": hex::encode(TRANSACTION),
                "hex": "0102",
                "height": 98,
                "confirmations": 4,
                "blockhash": display_hash(BLOCK),
            }),
        ));
        steps.push(ok("getblockhash", json!([98]), json!(display_hash(BLOCK))));
        let race_rpc = Arc::new(ScriptedRpc::new(steps));
        assert_eq!(
            authority(Chain::Wcash, Arc::clone(&race_rpc))
                .snapshot(&[watch()])
                .await,
            Err(ObservationFailure::Unavailable)
        );
        race_rpc.assert_drained();
    }

    #[tokio::test]
    async fn broadcast_succeeds_only_after_exact_authoritative_lookup() {
        let artifact = signed_artifact();
        let mut steps = Vec::new();
        push_tip(&mut steps, WCASH_TESTNET_BRANCH_ID, TIP, 100);
        steps.push(failure(
            "getrawtransaction",
            json!([hex::encode(TRANSACTION), 1]),
            RpcFailure::Server(-5),
        ));
        steps.push(ok(
            "sendrawtransaction",
            json!(["0102"]),
            json!(hex::encode(TRANSACTION)),
        ));
        steps.push(ok(
            "getrawtransaction",
            json!([hex::encode(TRANSACTION), 1]),
            json!({ "txid": hex::encode(TRANSACTION), "hex": "0102" }),
        ));
        push_tip(&mut steps, WCASH_TESTNET_BRANCH_ID, TIP, 100);
        let rpc = Arc::new(ScriptedRpc::new(steps));
        let broadcaster =
            RpcExactBroadcaster::new(Arc::new(authority(Chain::Wcash, Arc::clone(&rpc))));

        broadcaster
            .rebroadcast_exact(&artifact)
            .await
            .expect("node proves exact transaction after submission");
        rpc.assert_drained();
    }

    #[tokio::test]
    async fn already_known_succeeds_only_for_exact_bytes_at_a_stable_tip() {
        let artifact = signed_artifact();
        let mut steps = Vec::new();
        push_tip(&mut steps, WCASH_TESTNET_BRANCH_ID, TIP, 100);
        steps.push(ok(
            "getrawtransaction",
            json!([hex::encode(TRANSACTION), 1]),
            json!({ "txid": hex::encode(TRANSACTION), "hex": "0102" }),
        ));
        push_tip(&mut steps, WCASH_TESTNET_BRANCH_ID, TIP, 100);
        let rpc = Arc::new(ScriptedRpc::new(steps));
        let broadcaster =
            RpcExactBroadcaster::new(Arc::new(authority(Chain::Wcash, Arc::clone(&rpc))));

        broadcaster
            .rebroadcast_exact(&artifact)
            .await
            .expect("exact existing bytes are authoritative");
        rpc.assert_drained();
    }

    #[tokio::test]
    async fn successful_submit_without_authoritative_lookup_remains_ambiguous() {
        let artifact = signed_artifact();
        let mut steps = Vec::new();
        push_tip(&mut steps, WCASH_TESTNET_BRANCH_ID, TIP, 100);
        steps.push(failure(
            "getrawtransaction",
            json!([hex::encode(TRANSACTION), 1]),
            RpcFailure::Server(-5),
        ));
        steps.push(ok(
            "sendrawtransaction",
            json!(["0102"]),
            json!(hex::encode(TRANSACTION)),
        ));
        steps.push(failure(
            "getrawtransaction",
            json!([hex::encode(TRANSACTION), 1]),
            RpcFailure::Server(-5),
        ));
        let rpc = Arc::new(ScriptedRpc::new(steps));
        let broadcaster =
            RpcExactBroadcaster::new(Arc::new(authority(Chain::Wcash, Arc::clone(&rpc))));

        assert_eq!(
            broadcaster.rebroadcast_exact(&artifact).await,
            Err(BoundaryFailure::Ambiguous)
        );
        rpc.assert_drained();
    }

    fn zallet_status() -> Value {
        json!({
            "node_tip": { "blockhash": display_hash(TIP), "height": 100 },
            "wallet_tip": { "blockhash": display_hash(TIP), "height": 100 },
            "fully_synced_height": 100,
            "locked": false,
        })
    }

    #[tokio::test]
    async fn zallet_observer_requires_exact_account_and_ironwood_only_balance() {
        let fingerprint = SeedFingerprint::from_seed(&[0x77; 32]).expect("valid test seed");
        let commitment = validated_parent_payout_address_commitment(ZEC_COLLECTOR)
            .expect("canonical Ironwood-capable Zcash Testnet UA");
        let steps = vec![
            ok("getwalletstatus", json!([]), zallet_status()),
            ok(
                "z_listaccounts",
                json!([false]),
                json!([{
                    "account_uuid": ACCOUNT.to_string(),
                    "name": "collector",
                    "seedfp": fingerprint.to_string(),
                    "zip32_account_index": 0,
                    "account": 0,
                }]),
            ),
            ok(
                "z_getaccount",
                json!([ACCOUNT.to_string()]),
                json!({
                    "account_uuid": ACCOUNT.to_string(),
                    "name": "collector",
                    "seedfp": fingerprint.to_string(),
                    "zip32_account_index": 0,
                    "addresses": [{
                        "diversifier_index": 0,
                        "ua": ZEC_COLLECTOR,
                    }],
                }),
            ),
            ok(
                "z_getbalanceforaccount",
                json!([ACCOUNT.to_string(), 100]),
                json!({
                    "pools": { "ironwood": { "valueZat": 42_000 } },
                    "minimum_confirmations": 100,
                }),
            ),
            ok("getwalletstatus", json!([]), zallet_status()),
        ];
        let rpc = Arc::new(ScriptedRpc::new(steps));
        let observer =
            ZalletObservationSource::with_client(rpc.clone(), ACCOUNT, 0, 100, commitment)
                .expect("valid Zallet policy");
        let observation = observer.observe().await.expect("exact wallet observation");

        assert_eq!(observation.chain, Chain::Zcash);
        assert_eq!(observation.wallet_spendable_zat, 42_000);
        assert_eq!(observation.best_tip_hash, TIP);
        assert_eq!(observation.best_tip_height, 100);
        assert_ne!(observation.wallet_state_digest, [0; 32]);
        rpc.assert_drained();
    }

    #[tokio::test]
    async fn zallet_fresh_gate_includes_pending_and_dust_authority() {
        let fingerprint = SeedFingerprint::from_seed(&[0x77; 32]).expect("valid test seed");
        let commitment = validated_parent_payout_address_commitment(ZEC_COLLECTOR)
            .expect("canonical Ironwood-capable Zcash Testnet UA");
        let mut steps = vec![
            ok("getwalletstatus", json!([]), zallet_status()),
            ok(
                "z_listaccounts",
                json!([false]),
                json!([{
                    "account_uuid": ACCOUNT.to_string(),
                    "name": "collector",
                    "seedfp": fingerprint.to_string(),
                    "zip32_account_index": 0,
                    "account": 0,
                }]),
            ),
            ok(
                "z_getaccount",
                json!([ACCOUNT.to_string()]),
                json!({
                    "account_uuid": ACCOUNT.to_string(),
                    "name": "collector",
                    "seedfp": fingerprint.to_string(),
                    "zip32_account_index": 0,
                    "addresses": [{
                        "diversifier_index": 0,
                        "ua": ZEC_COLLECTOR,
                    }],
                }),
            ),
            ok(
                "z_getbalanceforaccount",
                json!([ACCOUNT.to_string(), 100]),
                json!({
                    "pools": {},
                    "minimum_confirmations": 100,
                }),
            ),
            ok("getwalletstatus", json!([]), zallet_status()),
            ok("getwalletstatus", json!([]), zallet_status()),
            ok(
                "z_getbalances",
                json!([0]),
                json!({
                    "accounts": [{
                        "account_uuid": ACCOUNT.to_string(),
                        "total": { "spendable": { "valueZat": 0 } },
                    }],
                }),
            ),
            ok("getwalletstatus", json!([]), zallet_status()),
        ];
        let rpc = Arc::new(ScriptedRpc::new(std::mem::take(&mut steps)));
        let observer =
            ZalletObservationSource::with_client(rpc.clone(), ACCOUNT, 0, 100, commitment)
                .expect("valid Zallet policy");
        let observation = observer
            .verify_fresh_zero()
            .await
            .expect("fresh dedicated collector is proven empty");
        assert_eq!(observation.wallet_spendable_zat, 0);
        rpc.assert_drained();

        for invalid in [
            json!({
                "accounts": [{
                    "account_uuid": ACCOUNT.to_string(),
                    "total": {
                        "spendable": { "valueZat": 0 },
                        "pending": { "valueZat": 1 },
                    },
                }],
            }),
            json!({
                "accounts": [{
                    "account_uuid": ACCOUNT.to_string(),
                    "ironwood": { "spendable": { "valueZat": 1 } },
                    "total": { "spendable": { "valueZat": 1 } },
                }],
            }),
            json!({
                "accounts": [{
                    "account_uuid": Uuid::new_v4().to_string(),
                    "total": { "spendable": { "valueZat": 0 } },
                }],
            }),
        ] {
            assert_eq!(
                parse_fresh_zero_balances(&invalid, ACCOUNT),
                Err(ObservationFailure::Invariant)
            );
        }
    }

    #[test]
    fn zallet_collector_commitment_is_exact_nonzero_and_unambiguous() {
        let fingerprint = SeedFingerprint::from_seed(&[0x77; 32]).expect("valid test seed");
        let commitment = validated_parent_payout_address_commitment(ZEC_COLLECTOR)
            .expect("canonical Ironwood-capable Zcash Testnet UA");
        let account = |addresses: Value| {
            serde_json::from_value::<DetailedAccount>(json!({
                "account_uuid": ACCOUNT.to_string(),
                "name": "collector",
                "seedfp": fingerprint.to_string(),
                "zip32_account_index": 0,
                "addresses": addresses,
            }))
            .expect("exact detailed account shape")
        };
        assert!(
            account(json!([{"diversifier_index": 0, "ua": ZEC_COLLECTOR}]))
                .verify(ACCOUNT, 0, fingerprint.to_bytes(), commitment)
                .is_ok()
        );
        assert_eq!(
            account(json!([{"diversifier_index": 0, "ua": ZEC_COLLECTOR}])).verify(
                ACCOUNT,
                0,
                fingerprint.to_bytes(),
                [0x5a; 32],
            ),
            Err(ObservationFailure::Invariant)
        );
        assert_eq!(
            account(json!([
                {"diversifier_index": 0, "ua": ZEC_COLLECTOR},
                {"diversifier_index": 1, "ua": ZEC_COLLECTOR},
            ]))
            .verify(ACCOUNT, 0, fingerprint.to_bytes(), commitment),
            Err(ObservationFailure::Invariant)
        );
        let mut reversed = commitment;
        reversed.reverse();
        assert_ne!(
            commitment, reversed,
            "commitment byte order must be visible"
        );

        assert!(matches!(
            ZalletObservationSource::with_client(
                Arc::new(ScriptedRpc::new(Vec::new())),
                ACCOUNT,
                0,
                100,
                [0; 32],
            ),
            Err(LivePayoutConfigError::AuthorityMismatch)
        ));
    }

    #[test]
    fn zallet_contract_rejects_explicit_null_and_legacy_pool_presence() {
        let mut status = zallet_status();
        status
            .as_object_mut()
            .expect("status object")
            .insert("wallet_tip".to_owned(), Value::Null);
        assert!(serde_json::from_value::<ZalletStatus>(status).is_err());

        assert_eq!(
            parse_ironwood_balance(
                &json!({
                    "pools": {
                        "ironwood": { "valueZat": 42_000 },
                        "orchard": { "valueZat": 1 },
                    },
                    "minimum_confirmations": 100,
                }),
                100,
            ),
            Err(ObservationFailure::Invariant)
        );
    }

    #[tokio::test]
    async fn loopback_rpc_emits_and_verifies_strict_json_rpc_envelope() {
        let directory = TempDirBuilder::new()
            .prefix(".rpc-cookie-test-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("temporary credential directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("protected directory");
        let cookie = directory.path().join("node.cookie");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&cookie)
            .expect("protected cookie");
        file.write_all(b"rpc-user:rpc-password\n")
            .expect("cookie bytes");
        drop(file);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let endpoint = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (mut stream, peer) = listener.accept().await.expect("one RPC connection");
            assert!(peer.ip().is_loopback());
            let mut request = Vec::new();
            let (boundary, content_length) = loop {
                if let Some(boundary) = find_bytes(&request, b"\r\n\r\n") {
                    let head =
                        std::str::from_utf8(&request[..boundary]).expect("HTTP request head");
                    assert!(head.starts_with("POST / HTTP/1.1\r\n"));
                    assert!(head.contains("Authorization: Basic cnBjLXVzZXI6cnBjLXBhc3N3b3Jk\r\n"));
                    assert!(head.contains("Content-Type: application/json\r\n"));
                    let length = head
                        .split("\r\n")
                        .find_map(|line| line.strip_prefix("Content-Length: "))
                        .and_then(|value| value.parse::<usize>().ok())
                        .expect("request content length");
                    break (boundary + 4, length);
                }
                let mut chunk = [0_u8; 1024];
                let read = stream.read(&mut chunk).await.expect("request bytes");
                assert!(read > 0);
                request.extend_from_slice(&chunk[..read]);
            };
            if request.len() < boundary + content_length {
                let start = request.len();
                request.resize(boundary + content_length, 0);
                stream
                    .read_exact(&mut request[start..])
                    .await
                    .expect("request body");
            }
            let request: Map<String, Value> =
                serde_json::from_slice(&request[boundary..boundary + content_length])
                    .expect("JSON-RPC request");
            assert_eq!(request.len(), 4);
            assert_eq!(request.get("jsonrpc"), Some(&json!("2.0")));
            assert_eq!(request.get("id"), Some(&json!(1)));
            assert_eq!(request.get("method"), Some(&json!("getblockhash")));
            assert_eq!(request.get("params"), Some(&json!([0])));

            let response = br#"{"jsonrpc":"2.0","id":1,"result":"ok"}"#;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            );
            stream
                .write_all(head.as_bytes())
                .await
                .expect("response head");
            stream.write_all(response).await.expect("response body");
        });

        let rpc = LoopbackJsonRpc::new(endpoint, cookie).expect("safe loopback boundary");
        assert_eq!(
            rpc.call("getblockhash", json!([0]), RpcLimits::compact())
                .await,
            Ok(json!("ok"))
        );
        server.await.expect("RPC server task");
    }
}
