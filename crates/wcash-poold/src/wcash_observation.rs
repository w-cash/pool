//! Wcash collector observation and database-clock reconciliation boundary.
//!
//! Wolf owns wallet scanning and emits one short-lived, seedless snapshot. This
//! module accepts that snapshot only from the integrity-pinned wallet process,
//! validates its complete 13-field contract against an independently configured
//! Testnet authority, and then lets PostgreSQL issue the reconciliation identity
//! against its own clock and ledger snapshot.

use std::time::Duration;

use serde::Deserialize;
use uuid::Uuid;
use wcash_pool_protocol::MAX_CHAIN_VALUE_ZAT;
use wcash_pool_store::{Chain, PostgresStore, StoreError, WalletObservation, WalletReconciliation};
use wcash_wec_payout_signer::{
    NativeWalletError, WalletFundSource, WalletNetwork, WCASH_TESTNET_BRANCH_ID,
    WCASH_TESTNET_GENESIS_HASH,
};

use crate::wec_wallet_transport::WolfWalletTransport;

const OBSERVATION_PROTOCOL_VERSION: u32 = 1;
const OBSERVATION_VALIDITY_SECS: u64 = 4 * 60;

/// Static authority which every Wcash collector observation must match.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservationAuthority {
    network: WalletNetwork,
    genesis_hash: String,
    branch_id: String,
    account_id: Uuid,
    fund_source: WalletFundSource,
}

/// Integrity-pinned, Testnet-only Wcash collector observer.
#[derive(Clone, Debug)]
pub struct WcashWalletObserver {
    wallet: WolfWalletTransport,
    authority: ObservationAuthority,
}

impl WcashWalletObserver {
    /// Binds an already verified Wolf executable to the exact configured wallet
    /// and Wcash Testnet consensus identity.
    ///
    /// `genesis_hash_wire` is the backend/configuration byte order. It is
    /// deliberately reversed before comparison with Wolf's conventional
    /// display-order response, preventing an accidental order mismatch from
    /// becoming a second accepted identity.
    pub fn new(
        wallet: WolfWalletTransport,
        network: WalletNetwork,
        genesis_hash_wire: [u8; 32],
        branch_id: impl Into<String>,
        account_id: Uuid,
        fund_source: WalletFundSource,
    ) -> Result<Self, WcashObservationConfigError> {
        let mut genesis_hash_display = genesis_hash_wire;
        genesis_hash_display.reverse();
        let genesis_hash = hex::encode(genesis_hash_display);
        let branch_id = branch_id.into();
        if network != WalletNetwork::Testnet
            || genesis_hash != WCASH_TESTNET_GENESIS_HASH
            || branch_id != WCASH_TESTNET_BRANCH_ID
            || account_id.is_nil()
            || fund_source != WalletFundSource::Ironwood
        {
            return Err(WcashObservationConfigError::AuthorityMismatch);
        }
        Ok(Self {
            wallet,
            authority: ObservationAuthority {
                network,
                genesis_hash,
                branch_id,
                account_id,
                fund_source,
            },
        })
    }

    /// Obtains and validates one short-lived wallet observation.
    ///
    /// This function intentionally does not compare timestamps with the host
    /// clock. PostgreSQL is the accounting clock authority and performs that
    /// check transactionally in [`PostgresStore::record_wallet_reconciliation`].
    pub fn observe(
        &self,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<WalletObservation, WcashObservationError> {
        let output = self
            .wallet
            .invoke_observation(timeout, max_response_bytes)
            .map_err(WcashObservationError::Wallet)?;
        let response: WireObservation = serde_json::from_slice(&output)
            .map_err(|_| WcashObservationError::Wallet(NativeWalletError::ProtocolViolation))?;
        self.parse_observation(response)
    }

    /// Records a validated observation against one exact PostgreSQL ledger
    /// snapshot and the database clock.
    ///
    /// The subprocess is isolated on a blocking worker so a slow wallet cannot
    /// block the async database or miner runtime. A reconciliation mismatch is
    /// handled by the store's existing durable payout-freeze semantics.
    pub async fn reconcile(
        &self,
        store: &PostgresStore,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<WalletReconciliation, WcashObservationError> {
        let observer = self.clone();
        let observation =
            tokio::task::spawn_blocking(move || observer.observe(timeout, max_response_bytes))
                .await
                .map_err(|_| WcashObservationError::WorkerUnavailable)??;
        store
            .record_wallet_reconciliation(&observation)
            .await
            .map_err(WcashObservationError::Store)
    }

    fn parse_observation(
        &self,
        response: WireObservation,
    ) -> Result<WalletObservation, WcashObservationError> {
        let invalid = || WcashObservationError::Wallet(NativeWalletError::ProtocolViolation);
        let response_network = match response.network.as_str() {
            "testnet" => WalletNetwork::Testnet,
            "regtest" => WalletNetwork::Regtest,
            "mainnet" => WalletNetwork::Mainnet,
            _ => return Err(invalid()),
        };
        let response_source = match response.fund_source.as_str() {
            "ironwood" => WalletFundSource::Ironwood,
            "sapling" => WalletFundSource::Sapling,
            "transparent" => WalletFundSource::Transparent,
            _ => return Err(invalid()),
        };
        let account_id = parse_canonical_uuid(&response.account_id).ok_or_else(invalid)?;
        let wallet_state_digest = parse_canonical_hex32(&response.wallet_state_digest)
            .filter(|digest| *digest != [0; 32])
            .ok_or_else(invalid)?;
        let best_tip_hash = parse_canonical_hex32(&response.best_tip_hash)
            .filter(|hash| *hash != [0; 32])
            .ok_or_else(invalid)?;
        let valid_window = response
            .valid_until
            .checked_sub(response.observed_at)
            .is_some_and(|seconds| seconds == OBSERVATION_VALIDITY_SECS);
        if response.protocol_version != OBSERVATION_PROTOCOL_VERSION
            || response_network != self.authority.network
            || response.genesis_hash != self.authority.genesis_hash
            || response.branch_id != self.authority.branch_id
            || account_id != self.authority.account_id
            || response_source != self.authority.fund_source
            || !response.synchronized
            || response.wallet_spendable_zat > MAX_CHAIN_VALUE_ZAT
            || response.best_tip_height == 0
            || response.observed_at == 0
            || !valid_window
        {
            return Err(invalid());
        }
        Ok(WalletObservation {
            chain: Chain::Wcash,
            wallet_state_digest,
            wallet_spendable_zat: response.wallet_spendable_zat,
            best_tip_hash,
            best_tip_height: response.best_tip_height,
            observed_at: response.observed_at,
            valid_until: response.valid_until,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireObservation {
    protocol_version: u32,
    network: String,
    genesis_hash: String,
    branch_id: String,
    account_id: String,
    fund_source: String,
    synchronized: bool,
    wallet_state_digest: String,
    wallet_spendable_zat: u64,
    best_tip_hash: String,
    best_tip_height: u32,
    observed_at: u64,
    valid_until: u64,
}

fn parse_canonical_uuid(value: &str) -> Option<Uuid> {
    let parsed = Uuid::parse_str(value).ok()?;
    (!parsed.is_nil() && parsed.to_string() == value).then_some(parsed)
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

/// Invalid static authority for the Wcash wallet observer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WcashObservationConfigError {
    /// Only the frozen Wcash Testnet, configured collector account, and
    /// Ironwood source are accepted by this release.
    #[error("Wcash observation authority does not match the frozen Testnet policy")]
    AuthorityMismatch,
}

/// Privacy-preserving Wcash collector observation failure.
#[derive(Debug, thiserror::Error)]
pub enum WcashObservationError {
    /// The integrity-pinned wallet process was unavailable or violated its
    /// machine protocol. The class contains no wallet or credential material.
    #[error("Wcash wallet observation failed: {0:?}")]
    Wallet(NativeWalletError),
    /// The isolated blocking worker did not return normally.
    #[error("Wcash wallet observation worker is unavailable")]
    WorkerUnavailable,
    /// PostgreSQL rejected or could not durably record the observation.
    #[error("Wcash wallet reconciliation was not recorded")]
    Store(#[source] StoreError),
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::{fs, path::PathBuf, time::Instant};

    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;
    use crate::wec_wallet_transport::PinnedWolfProgram;

    const ACCOUNT: &str = "10000000-0000-4000-8000-000000000001";

    fn genesis_wire() -> [u8; 32] {
        let mut bytes: [u8; 32] = hex::decode(WCASH_TESTNET_GENESIS_HASH)
            .unwrap()
            .try_into()
            .unwrap();
        bytes.reverse();
        bytes
    }

    fn valid_response() -> Value {
        json!({
            "protocol_version": 1,
            "network": "testnet",
            "genesis_hash": WCASH_TESTNET_GENESIS_HASH,
            "branch_id": WCASH_TESTNET_BRANCH_ID,
            "account_id": ACCOUNT,
            "fund_source": "ironwood",
            "synchronized": true,
            "wallet_state_digest": "11".repeat(32),
            "wallet_spendable_zat": 625_000_000_u64,
            "best_tip_hash": "22".repeat(32),
            "best_tip_height": 42_u32,
            "observed_at": 1_725_000_000_u64,
            "valid_until": 1_725_000_240_u64
        })
    }

    #[cfg(unix)]
    fn fixture_observer(shell_body: &str) -> (tempfile::TempDir, PathBuf, WcashWalletObserver) {
        let directory = tempfile::tempdir().unwrap();
        let canonical_directory = fs::canonicalize(directory.path()).unwrap();
        let program_path = canonical_directory.join("wcash-wallet-fixture");
        fs::write(&program_path, format!("#!/bin/sh\n{shell_body}\n")).unwrap();
        fs::set_permissions(&program_path, fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(&program_path).unwrap();
        let digest: [u8; 32] = Sha256::digest(fs::read(&program_path).unwrap()).into();
        let program = PinnedWolfProgram::verify(&program_path, digest, metadata.uid()).unwrap();
        let wallet = WolfWalletTransport::new(
            program,
            canonical_directory.join("wallet.sqlite"),
            "http://127.0.0.1:38234",
        )
        .unwrap();
        let observer = WcashWalletObserver::new(
            wallet,
            WalletNetwork::Testnet,
            genesis_wire(),
            WCASH_TESTNET_BRANCH_ID,
            Uuid::parse_str(ACCOUNT).unwrap(),
            WalletFundSource::Ironwood,
        )
        .unwrap();
        (directory, program_path, observer)
    }

    #[cfg(unix)]
    fn response_observer(response: &Value) -> (tempfile::TempDir, PathBuf, WcashWalletObserver) {
        let script = format!("printf '%s' '{}'", response);
        fixture_observer(&script)
    }

    fn parse_value(
        observer: &WcashWalletObserver,
        response: Value,
    ) -> Result<WalletObservation, WcashObservationError> {
        let response = serde_json::from_value(response)
            .map_err(|_| WcashObservationError::Wallet(NativeWalletError::ProtocolViolation))?;
        observer.parse_observation(response)
    }

    #[test]
    fn constructor_rejects_every_alternate_authority_domain() {
        let (_directory, _program, valid) = fixture_observer("printf '{}'");
        let wallet = valid.wallet;
        let account = Uuid::parse_str(ACCOUNT).unwrap();
        let cases = [
            (
                WalletNetwork::Mainnet,
                genesis_wire(),
                WCASH_TESTNET_BRANCH_ID,
                account,
                WalletFundSource::Ironwood,
            ),
            (
                WalletNetwork::Testnet,
                [9; 32],
                WCASH_TESTNET_BRANCH_ID,
                account,
                WalletFundSource::Ironwood,
            ),
            (
                WalletNetwork::Testnet,
                genesis_wire(),
                "deadbeef",
                account,
                WalletFundSource::Ironwood,
            ),
            (
                WalletNetwork::Testnet,
                genesis_wire(),
                WCASH_TESTNET_BRANCH_ID,
                Uuid::nil(),
                WalletFundSource::Ironwood,
            ),
            (
                WalletNetwork::Testnet,
                genesis_wire(),
                WCASH_TESTNET_BRANCH_ID,
                account,
                WalletFundSource::Transparent,
            ),
        ];
        for (network, genesis, branch, account, source) in cases {
            assert!(matches!(
                WcashWalletObserver::new(wallet.clone(), network, genesis, branch, account, source,),
                Err(WcashObservationConfigError::AuthorityMismatch)
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_observation_maps_exactly_to_wcash_store_facts() {
        let response = valid_response();
        let (_directory, _program, observer) = response_observer(&response);
        let observed = observer.observe(Duration::from_secs(5), 4_096).unwrap();
        assert_eq!(
            observed,
            WalletObservation {
                chain: Chain::Wcash,
                wallet_state_digest: [0x11; 32],
                wallet_spendable_zat: 625_000_000,
                best_tip_hash: [0x22; 32],
                best_tip_height: 42,
                observed_at: 1_725_000_000,
                valid_until: 1_725_000_240,
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn every_missing_or_additional_field_is_rejected() {
        let (_directory, _program, observer) = fixture_observer("printf '{}'");
        let field_names = valid_response()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(field_names.len(), 13);
        for field in field_names {
            let mut response = valid_response();
            response.as_object_mut().unwrap().remove(&field);
            assert!(matches!(
                parse_value(&observer, response),
                Err(WcashObservationError::Wallet(
                    NativeWalletError::ProtocolViolation
                ))
            ));
        }
        let mut response = valid_response();
        response["unexpected"] = json!(true);
        assert!(matches!(
            parse_value(&observer, response),
            Err(WcashObservationError::Wallet(
                NativeWalletError::ProtocolViolation
            ))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn altered_identity_state_tip_and_time_fields_fail_closed() {
        let (_directory, _program, observer) = fixture_observer("printf '{}'");
        let mutations = [
            ("protocol_version", json!(2)),
            ("network", json!("mainnet")),
            ("genesis_hash", json!("33".repeat(32))),
            ("branch_id", json!("deadbeef")),
            ("account_id", json!("20000000-0000-4000-8000-000000000002")),
            ("fund_source", json!("transparent")),
            ("synchronized", json!(false)),
            ("wallet_state_digest", json!("00".repeat(32))),
            ("wallet_spendable_zat", json!(MAX_CHAIN_VALUE_ZAT + 1)),
            ("best_tip_hash", json!("00".repeat(32))),
            ("best_tip_height", json!(0)),
            ("observed_at", json!(0)),
            ("valid_until", json!(1_725_000_241_u64)),
        ];
        for (field, replacement) in mutations {
            let mut response = valid_response();
            response[field] = replacement;
            assert!(
                matches!(
                    parse_value(&observer, response),
                    Err(WcashObservationError::Wallet(
                        NativeWalletError::ProtocolViolation
                    ))
                ),
                "field {field} was accepted"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_stderr_nonzero_timeout_and_size_fail_closed() {
        let stderr_script = format!(
            "printf '%s' '{}'; printf '%s' 'unexpected diagnostic' >&2",
            valid_response()
        );
        let (_directory, _program, observer) = fixture_observer(&stderr_script);
        assert!(matches!(
            observer.observe(Duration::from_secs(5), 4_096),
            Err(WcashObservationError::Wallet(
                NativeWalletError::ProtocolViolation
            ))
        ));

        let failure = json!({
            "protocol_version": 1,
            "code": "unavailable",
            "error": "fixture unavailable"
        });
        let script = format!(
            "printf '%s' '{}'; printf '%s' '{}' >&2; exit 1",
            valid_response(),
            failure
        );
        let (_directory, _program, observer) = fixture_observer(&script);
        assert!(matches!(
            observer.observe(Duration::from_secs(5), 4_096),
            Err(WcashObservationError::Wallet(
                NativeWalletError::Unavailable
            ))
        ));

        let (_directory, _program, observer) = fixture_observer("exec /bin/sleep 5");
        let started = Instant::now();
        assert!(matches!(
            observer.observe(Duration::from_millis(25), 4_096),
            Err(WcashObservationError::Wallet(NativeWalletError::Timeout))
        ));
        assert!(started.elapsed() < Duration::from_secs(1));

        let oversized = "a".repeat(2_048);
        let script = format!("printf '%s' '{oversized}'");
        let (_directory, _program, observer) = fixture_observer(&script);
        assert!(matches!(
            observer.observe(Duration::from_secs(5), 1_024),
            Err(WcashObservationError::Wallet(
                NativeWalletError::ProtocolViolation
            ))
        ));
    }
}
