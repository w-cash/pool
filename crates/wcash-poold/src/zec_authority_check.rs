//! One-time, pre-backend-init Zcash Testnet collector authority gate.
//!
//! This check is intentionally independent of the backend authority and
//! accounting database. It proves that a finalized, dedicated Zallet
//! collector is empty and bound to the expected Zcash Testnet authority before
//! the backend is allowed to seal its durable identity.

use std::{
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wcash_pool_store::{Chain, WalletObservation};

use crate::{
    config::read_protected,
    live_payout::{
        LivePayoutConfigError, LoopbackJsonRpc, NodePayoutAuthority, ZalletObservationSource,
        ZCASH_NU6_3_BRANCH_ID,
    },
    payout_runtime::{AuthoritySnapshot, ObservationFailure, PayoutConfirmationAuthority},
};

const MAX_AUTHORITY_CONFIG_BYTES: u64 = 16 * 1024;
/// A non-secret success record suitable for a bounded bootstrap log.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ZecAuthoritySummary {
    authority_verified: bool,
    network: &'static str,
    consensus_branch_id: &'static str,
    collector_pool: &'static str,
    initial_balance_zat: u64,
    tip_height: u32,
    tip_hash: String,
}

impl ZecAuthoritySummary {
    pub(crate) fn to_json(&self) -> Result<String, ZecAuthorityCheckError> {
        let encoded =
            serde_json::to_string(self).map_err(|_| ZecAuthorityCheckError::AuthorityRejected)?;
        // Every variable-width field is fixed above. Keep a defensive bound so
        // future changes cannot accidentally turn this bootstrap output into a
        // wallet-data disclosure surface.
        if encoded.len() > 512 {
            return Err(ZecAuthorityCheckError::AuthorityRejected);
        }
        Ok(encoded)
    }
}

/// Standalone configuration available before Wolf seals its backend identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ZecAuthorityConfig {
    zcash_genesis_wire: [u8; 32],
    collector_payout_commitment: [u8; 32],
    collector_account: Uuid,
    collector_account_index: u32,
    required_confirmations: u32,
    zallet_rpc: SocketAddr,
    zallet_cookie_file: PathBuf,
    zcash_node_rpc: SocketAddr,
    zcash_node_cookie_file: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawZecAuthorityConfig {
    network: String,
    zcash_genesis_wire: String,
    collector_payout_commitment: String,
    collector_account: String,
    collector_account_index: u32,
    required_confirmations: u32,
    zallet_rpc: SocketAddr,
    zallet_cookie_file: PathBuf,
    zcash_node_rpc: SocketAddr,
    zcash_node_cookie_file: PathBuf,
}

impl ZecAuthorityConfig {
    pub(crate) fn load(path: &Path) -> Result<Self, ZecAuthorityCheckError> {
        let bytes = read_protected(path, MAX_AUTHORITY_CONFIG_BYTES, false)
            .map_err(|_| ZecAuthorityCheckError::UnsafeConfiguration)?;
        let source =
            std::str::from_utf8(&bytes).map_err(|_| ZecAuthorityCheckError::UnsafeConfiguration)?;
        let raw: RawZecAuthorityConfig =
            toml::from_str(source).map_err(|_| ZecAuthorityCheckError::UnsafeConfiguration)?;
        Self::try_from(raw)
    }
}

impl TryFrom<RawZecAuthorityConfig> for ZecAuthorityConfig {
    type Error = ZecAuthorityCheckError;

    fn try_from(raw: RawZecAuthorityConfig) -> Result<Self, Self::Error> {
        let zcash_genesis_wire = canonical_hex32(&raw.zcash_genesis_wire)?;
        let collector_payout_commitment = canonical_hex32(&raw.collector_payout_commitment)?;
        let collector_account = canonical_uuid(&raw.collector_account)?;
        if raw.network != "testnet"
            || raw.collector_account_index >= (1 << 31)
            || !(100..=1_000_000).contains(&raw.required_confirmations)
            || raw.zallet_rpc == raw.zcash_node_rpc
            || !safe_loopback(raw.zallet_rpc)
            || !safe_loopback(raw.zcash_node_rpc)
            || !absolute_normalized(&raw.zallet_cookie_file)
            || !absolute_normalized(&raw.zcash_node_cookie_file)
            || raw.zallet_cookie_file == raw.zcash_node_cookie_file
        {
            return Err(ZecAuthorityCheckError::UnsafeConfiguration);
        }
        Ok(Self {
            zcash_genesis_wire,
            collector_payout_commitment,
            collector_account,
            collector_account_index: raw.collector_account_index,
            required_confirmations: raw.required_confirmations,
            zallet_rpc: raw.zallet_rpc,
            zallet_cookie_file: raw.zallet_cookie_file,
            zcash_node_rpc: raw.zcash_node_rpc,
            zcash_node_cookie_file: raw.zcash_node_cookie_file,
        })
    }
}

fn canonical_hex32(encoded: &str) -> Result<[u8; 32], ZecAuthorityCheckError> {
    if encoded.len() != 64
        || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit())
        || encoded.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(ZecAuthorityCheckError::UnsafeConfiguration);
    }
    let decoded: [u8; 32] = hex::decode(encoded)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .filter(|bytes: &[u8; 32]| *bytes != [0; 32])
        .ok_or(ZecAuthorityCheckError::UnsafeConfiguration)?;
    if hex::encode(decoded) != encoded {
        return Err(ZecAuthorityCheckError::UnsafeConfiguration);
    }
    Ok(decoded)
}

fn canonical_uuid(encoded: &str) -> Result<Uuid, ZecAuthorityCheckError> {
    Uuid::parse_str(encoded)
        .ok()
        .filter(|parsed| !parsed.is_nil() && parsed.to_string() == encoded)
        .ok_or(ZecAuthorityCheckError::UnsafeConfiguration)
}

fn safe_loopback(endpoint: SocketAddr) -> bool {
    endpoint.ip().is_loopback() && endpoint.port() != 0
}

fn absolute_normalized(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
}

/// Proves one fresh ZEC collector without requiring a database or Wolf state.
pub(crate) async fn check(
    config: &ZecAuthorityConfig,
) -> Result<ZecAuthoritySummary, ZecAuthorityCheckError> {
    let zallet_rpc = Arc::new(
        LoopbackJsonRpc::new(config.zallet_rpc, config.zallet_cookie_file.clone())
            .map_err(map_config_error)?,
    );
    let node_rpc = Arc::new(
        LoopbackJsonRpc::new(config.zcash_node_rpc, config.zcash_node_cookie_file.clone())
            .map_err(map_config_error)?,
    );
    let collector = ZalletObservationSource::new(
        zallet_rpc,
        config.collector_account,
        config.collector_account_index,
        config.required_confirmations,
        config.collector_payout_commitment,
    )
    .map_err(map_config_error)?;
    let node = NodePayoutAuthority::new(Chain::Zcash, node_rpc, config.zcash_genesis_wire)
        .map_err(map_config_error)?;

    node.startup_probe().await.map_err(map_observation_error)?;
    let before = node.snapshot(&[]).await.map_err(map_observation_error)?;
    let observation = collector
        .verify_fresh_zero()
        .await
        .map_err(map_observation_error)?;
    let after = node.snapshot(&[]).await.map_err(map_observation_error)?;
    validate_exact_common_tip(&observation, &before, &after)
}

fn validate_exact_common_tip(
    observation: &WalletObservation,
    before: &AuthoritySnapshot,
    after: &AuthoritySnapshot,
) -> Result<ZecAuthoritySummary, ZecAuthorityCheckError> {
    if observation.chain != Chain::Zcash
        || before.chain != Chain::Zcash
        || after.chain != Chain::Zcash
        || observation.wallet_spendable_zat != 0
        || observation.wallet_state_digest == [0; 32]
        || observation.observed_at == 0
        || observation.valid_until <= observation.observed_at
        || before.observed_at == 0
        || after.observed_at == 0
        || before.observed_at > observation.observed_at
        || observation.observed_at > after.observed_at
        || after.observed_at >= observation.valid_until
        || !before.payouts.is_empty()
        || !after.payouts.is_empty()
        || before.best_tip_height == 0
        || before.best_tip_hash == [0; 32]
        || before.best_tip_height != after.best_tip_height
        || before.best_tip_hash != after.best_tip_hash
        || observation.best_tip_height != before.best_tip_height
        || observation.best_tip_hash != before.best_tip_hash
    {
        return Err(ZecAuthorityCheckError::AuthorityRejected);
    }

    let mut display_hash = before.best_tip_hash;
    display_hash.reverse();
    Ok(ZecAuthoritySummary {
        authority_verified: true,
        network: "testnet",
        consensus_branch_id: ZCASH_NU6_3_BRANCH_ID,
        collector_pool: "ironwood",
        initial_balance_zat: 0,
        tip_height: before.best_tip_height,
        tip_hash: hex::encode(display_hash),
    })
}

fn map_config_error(_: LivePayoutConfigError) -> ZecAuthorityCheckError {
    ZecAuthorityCheckError::UnsafeConfiguration
}

fn map_observation_error(error: ObservationFailure) -> ZecAuthorityCheckError {
    match error {
        ObservationFailure::Unavailable => ZecAuthorityCheckError::AuthorityUnavailable,
        ObservationFailure::Invariant => ZecAuthorityCheckError::AuthorityRejected,
    }
}

/// Deliberately low-information failure classes for system service logs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ZecAuthorityCheckError {
    #[error("ZEC authority configuration is unsafe")]
    UnsafeConfiguration,
    #[error("ZEC authority is temporarily unavailable")]
    AuthorityUnavailable,
    #[error("ZEC authority failed its immutable Testnet contract")]
    AuthorityRejected,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use tempfile::Builder as TempDirBuilder;

    use super::*;

    fn fixture() -> RawZecAuthorityConfig {
        RawZecAuthorityConfig {
            network: "testnet".to_owned(),
            zcash_genesis_wire: "11".repeat(32),
            collector_payout_commitment: "22".repeat(32),
            collector_account: "11111111-1111-4111-8111-111111111111".to_owned(),
            collector_account_index: 0,
            required_confirmations: 100,
            zallet_rpc: "127.0.0.1:28232".parse().expect("fixture socket"),
            zallet_cookie_file: PathBuf::from("/run/credentials/zallet/cookie"),
            zcash_node_rpc: "127.0.0.1:18242".parse().expect("fixture socket"),
            zcash_node_cookie_file: PathBuf::from("/run/credentials/zebra/cookie"),
        }
    }

    fn observation() -> WalletObservation {
        WalletObservation {
            chain: Chain::Zcash,
            wallet_state_digest: [3; 32],
            wallet_spendable_zat: 0,
            best_tip_hash: tip_wire(),
            best_tip_height: 42,
            observed_at: 100,
            valid_until: 200,
        }
    }

    fn snapshot(observed_at: u64) -> AuthoritySnapshot {
        AuthoritySnapshot {
            chain: Chain::Zcash,
            best_tip_hash: tip_wire(),
            best_tip_height: 42,
            observed_at,
            payouts: Vec::new(),
        }
    }

    fn tip_wire() -> [u8; 32] {
        std::array::from_fn(|index| u8::try_from(index + 1).expect("bounded test index"))
    }

    #[test]
    fn accepts_only_a_finalized_standalone_testnet_policy() {
        let parsed = ZecAuthorityConfig::try_from(fixture()).expect("valid fixture");
        assert_eq!(parsed.collector_account_index, 0);

        let mut invalid = fixture();
        invalid.network = "mainnet".to_owned();
        assert_eq!(
            ZecAuthorityConfig::try_from(invalid),
            Err(ZecAuthorityCheckError::UnsafeConfiguration)
        );

        let mut invalid = fixture();
        invalid.collector_account = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA".to_owned();
        assert_eq!(
            ZecAuthorityConfig::try_from(invalid),
            Err(ZecAuthorityCheckError::UnsafeConfiguration)
        );

        let mut invalid = fixture();
        invalid.collector_account = Uuid::nil().to_string();
        assert_eq!(
            ZecAuthorityConfig::try_from(invalid),
            Err(ZecAuthorityCheckError::UnsafeConfiguration)
        );

        let mut invalid = fixture();
        invalid.zcash_genesis_wire = "AA".repeat(32);
        assert_eq!(
            ZecAuthorityConfig::try_from(invalid),
            Err(ZecAuthorityCheckError::UnsafeConfiguration)
        );

        let mut invalid = fixture();
        invalid.zcash_node_rpc = invalid.zallet_rpc;
        assert_eq!(
            ZecAuthorityConfig::try_from(invalid),
            Err(ZecAuthorityCheckError::UnsafeConfiguration)
        );
    }

    #[test]
    fn loads_a_protected_dedicated_policy_and_rejects_schema_extensions() {
        let directory = TempDirBuilder::new()
            .prefix(".zec-authority-policy-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("temporary policy directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("protected directory");
        let policy = directory.path().join("zec-authority.toml");
        let source = format!(
            r#"network = "testnet"
zcash_genesis_wire = "{}"
collector_payout_commitment = "{}"
collector_account = "11111111-1111-4111-8111-111111111111"
collector_account_index = 0
required_confirmations = 100
zallet_rpc = "127.0.0.1:28232"
zallet_cookie_file = "/run/credentials/zallet/cookie"
zcash_node_rpc = "127.0.0.1:18242"
zcash_node_cookie_file = "/run/credentials/zebra/cookie"
"#,
            "11".repeat(32),
            "22".repeat(32),
        );
        fs::write(&policy, &source).expect("policy fixture");
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o644)).expect("protected policy");
        assert!(ZecAuthorityConfig::load(&policy).is_ok());

        let extended = format!("{source}unexpected = true\n");
        assert!(toml::from_str::<RawZecAuthorityConfig>(&extended).is_err());
    }

    #[test]
    fn binds_wallet_and_node_to_one_exact_stable_tip() {
        let accepted = validate_exact_common_tip(&observation(), &snapshot(99), &snapshot(101))
            .expect("exact common tip");
        assert!(accepted.authority_verified);
        assert_eq!(accepted.initial_balance_zat, 0);
        assert_eq!(accepted.tip_height, 42);

        let mut changed = snapshot(101);
        changed.best_tip_height += 1;
        assert_eq!(
            validate_exact_common_tip(&observation(), &snapshot(99), &changed),
            Err(ZecAuthorityCheckError::AuthorityRejected)
        );

        let mut funded = observation();
        funded.wallet_spendable_zat = 1;
        assert_eq!(
            validate_exact_common_tip(&funded, &snapshot(99), &snapshot(101)),
            Err(ZecAuthorityCheckError::AuthorityRejected)
        );

        let mut stale = observation();
        stale.valid_until = 101;
        assert_eq!(
            validate_exact_common_tip(&stale, &snapshot(99), &snapshot(101)),
            Err(ZecAuthorityCheckError::AuthorityRejected)
        );
    }

    #[test]
    fn success_output_is_bounded_and_excludes_wallet_identity() {
        let summary = validate_exact_common_tip(&observation(), &snapshot(99), &snapshot(101))
            .expect("exact common tip");
        let encoded = summary.to_json().expect("bounded JSON");
        assert!(encoded.len() <= 512);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&encoded).expect("valid JSON"),
            serde_json::json!({
                "authority_verified": true,
                "network": "testnet",
                "consensus_branch_id": "37a5165b",
                "collector_pool": "ironwood",
                "initial_balance_zat": 0,
                "tip_height": 42,
                "tip_hash": "201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201"
            })
        );
        assert!(!encoded.contains("11111111-1111-4111-8111-111111111111"));
        assert!(!encoded.contains("commitment"));
        assert!(!encoded.contains("address"));
        assert!(!encoded.contains("seed"));
    }
}
