//! Strict daemon configuration and protected credential loading.

use std::{
    ffi::OsStr,
    fs::File,
    io::Read,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use num_bigint::BigUint;
use rustix::{
    fs::{fstat, openat, statat, AtFlags, FileType, Mode, OFlags, Stat, CWD},
    process::geteuid,
};
use serde::Deserialize;
use uuid::Uuid;
use wcash_pool_portal::ChainNetwork;
use wcash_pool_store::MiningAuthenticationMode;
use zeroize::Zeroizing;

const MAX_CONFIG_BYTES: u64 = 128 * 1024;
const MAX_CREDENTIAL_BYTES: u64 = 16 * 1024;
pub(crate) const MAX_WCASH_WALLET_SYNC_TIMEOUT: Duration = Duration::from_secs(900);
const WCASH_MAINNET_GENESIS: &str =
    "5bae12c8662a577b04ce1591af1a137c128f0cb51018a5f1622d861d1bb6fc48";
const ZCASH_MAINNET_GENESIS: &str =
    "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08";
const WCASH_AUXILIARY_CHAIN_ID: u32 = 0x5743_4153;

/// Fully decoded, immutable service policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeConfig {
    /// Explicit chain environment; Regtest exists only in integration builds.
    pub network: ChainNetwork,
    /// Stable database namespace.
    pub deployment_id: Uuid,
    /// Stable pool process identity used by Wolf receipts and nonce leases.
    pub pool_instance: Uuid,
    /// Stable Wolf installation identity.
    pub backend_instance: Uuid,
    /// Stable Wolf journal identity.
    pub journal_stream: Uuid,
    /// Wcash AuxPoW chain identifier.
    pub chain_id: u32,
    /// Wcash Testnet genesis hash in backend wire order.
    pub wcash_genesis: [u8; 32],
    /// Zcash Testnet genesis hash in backend wire order.
    pub zcash_genesis: [u8; 32],
    /// Exact private WEC collector commitment.
    pub wcash_payout_commitment: [u8; 32],
    /// Exact ZEC collector commitment.
    pub zcash_payout_commitment: [u8; 32],
    /// Protected Wolf backend Unix socket.
    pub backend_socket: PathBuf,
    /// Protected PostgreSQL connection credential.
    pub database_url_file: PathBuf,
    /// Public plaintext ZIP-301 compatibility listener.
    pub stratum_listen: SocketAddr,
    /// Loopback-only miner portal listener.
    pub portal_listen: SocketAddr,
    /// Exact public HTTPS portal origin.
    pub portal_origin: String,
    /// Explicit Mainnet self-service registration gate; closed by default.
    pub registration_open: bool,
    /// Safety hold applied to every initial or replacement payout destination.
    pub payout_change_hold_secs: u64,
    /// Non-zero, deployment-exclusive nonce namespace.
    pub nonce_namespace: u8,
    /// Number of nonce prefixes reserved transactionally per start.
    pub nonce_reservation: u64,
    /// Bounded PostgreSQL connection count.
    pub database_connections: u32,
    /// Process-wide live miner ceiling.
    pub maximum_miners: usize,
    /// Per-source live miner ceiling.
    pub maximum_miners_per_ip: usize,
    /// Concurrent Argon2 verification ceiling.
    pub authentication_parallelism: usize,
    /// Explicit miner authorization policy.
    pub mining_authentication: MiningAuthenticationMode,
    /// Integrity-pinned Wolf address command.
    pub wcash_wallet_program: PathBuf,
    /// Expected executable digest.
    pub wcash_wallet_sha256: [u8; 32],
    /// Required executable owner.
    pub wcash_wallet_uid: u32,
    /// Whether spending-key-backed automatic payout execution is online.
    pub payout_mode: PayoutMode,
    /// Spending authority used only when automatic payouts are explicitly enabled.
    pub automatic_payout: Option<AutomaticPayoutConfig>,
    /// Loopback Wcash validator JSON-RPC endpoint.
    pub wcash_node_rpc: SocketAddr,
    /// Protected Wcash validator JSON-RPC cookie.
    pub wcash_node_cookie_file: PathBuf,
    /// Loopback Zebra JSON-RPC endpoint used for exact ZEC broadcast.
    pub zcash_node_rpc: SocketAddr,
    /// Protected Zebra JSON-RPC cookie.
    pub zcash_node_cookie_file: PathBuf,
    /// Portal keyed-digest secret credential.
    pub portal_token_pepper_file: PathBuf,
    /// Portal TOTP encryption secret credential.
    pub portal_totp_key_file: PathBuf,
    /// Initial Wcash accounting policy.
    pub wcash_policy: ChainRuntimePolicy,
    /// Initial Zcash accounting policy.
    pub zcash_policy: ChainRuntimePolicy,
    /// Initial miner share target in canonical big-endian order.
    pub initial_share_target_be: [u8; 32],
    /// Easiest permitted miner share target in canonical big-endian order.
    pub easiest_share_target_be: [u8; 32],
}

/// Mining and payout execution are deliberately separate availability domains.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PayoutMode {
    /// Record exact liabilities without collector spending authority in this process.
    Deferred,
    /// Run the separately fenced automatic payout workers.
    Automatic,
}

/// Spending-key-backed runtime inputs, absent from a deferred mining process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomaticPayoutConfig {
    /// Independently enabled payout chains. Mainnet may start with WEC only.
    pub chains: Vec<AutomaticPayoutChain>,
    /// Persistent native Wcash collector wallet database.
    pub wcash_wallet_database: PathBuf,
    /// Literal loopback Wcash compact-block endpoint.
    pub wcash_lightwalletd_endpoint: String,
    /// Maximum compact blocks requested in one seedless wallet-sync batch.
    pub wcash_wallet_sync_batch_size: u32,
    /// Independent wall-clock limit for one complete seedless wallet sync.
    pub wcash_wallet_sync_timeout: Duration,
    /// Protected Wcash collector seed credential.
    pub wcash_wallet_seed_file: PathBuf,
    /// Required owner of the Wcash seed credential.
    pub wcash_seed_uid: u32,
    /// Crash-recovery journal for exact WEC payout artifacts.
    pub wcash_signer_journal_directory: PathBuf,
    /// Exact Wcash collector account identity.
    pub wcash_signer_account: Uuid,
    /// Exact one-time collector surplus to recognize as pool equity before the
    /// first reconciliation. Zero disables opening-balance recognition.
    pub wcash_opening_pool_equity_zat: u64,
}

/// One independently enabled automatic payout chain.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AutomaticPayoutChain {
    /// Wcash Ironwood payouts.
    Wcash,
    /// Zcash payouts through Zallet.
    Zcash,
}

/// Explicit zero-fee launch policy for one independently settled chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainRuntimePolicy {
    /// Exact normalized PPLNS window work.
    pub pplns_window_work: BigUint,
    /// Automatic payout floor in atomic units.
    pub payout_threshold_zat: u64,
    /// Conservative maturity and reorganization depth.
    pub required_confirmations: u32,
    /// Maximum recipients in one deterministic batch.
    pub maximum_payout_outputs: u32,
    /// Maximum gross amount paid to one account in one transaction.
    pub maximum_payout_zat: u64,
    /// Absolute transaction fee ceiling.
    pub maximum_network_fee_zat: u64,
    /// Relative transaction fee ceiling in basis points.
    pub maximum_network_fee_bps: u16,
    /// Immutable launch revision.
    pub policy_version: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawChainPolicy {
    pplns_window_work: String,
    payout_threshold_zat: u64,
    required_confirmations: u32,
    maximum_payout_outputs: u32,
    maximum_payout_zat: u64,
    maximum_network_fee_zat: u64,
    maximum_network_fee_bps: u16,
    policy_version: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    network: String,
    deployment_id: Uuid,
    pool_instance: Uuid,
    backend_instance: Uuid,
    journal_stream: Uuid,
    chain_id: u32,
    wcash_genesis: String,
    zcash_genesis: String,
    wcash_payout_commitment: String,
    zcash_payout_commitment: String,
    backend_socket: PathBuf,
    database_url_file: PathBuf,
    stratum_listen: SocketAddr,
    portal_listen: SocketAddr,
    portal_origin: String,
    #[serde(default)]
    registration_open: bool,
    payout_change_hold_secs: u64,
    nonce_namespace: u8,
    nonce_reservation: u64,
    database_connections: u32,
    maximum_miners: usize,
    maximum_miners_per_ip: usize,
    authentication_parallelism: usize,
    #[serde(default = "default_mining_authentication")]
    mining_authentication: RawMiningAuthenticationMode,
    wcash_wallet_program: PathBuf,
    wcash_wallet_sha256: String,
    wcash_wallet_uid: u32,
    payout_mode: PayoutMode,
    #[serde(default)]
    automatic_payout_chains: Vec<AutomaticPayoutChain>,
    wcash_wallet_database: Option<PathBuf>,
    wcash_lightwalletd_endpoint: Option<String>,
    wcash_wallet_sync_batch_size: Option<u32>,
    wcash_wallet_sync_timeout_seconds: Option<u64>,
    wcash_node_rpc: SocketAddr,
    wcash_node_cookie_file: PathBuf,
    wcash_wallet_seed_file: Option<PathBuf>,
    wcash_seed_uid: Option<u32>,
    wcash_signer_journal_directory: Option<PathBuf>,
    wcash_signer_account: Option<Uuid>,
    #[serde(default)]
    wcash_opening_pool_equity_zat: u64,
    zallet_configuration: Option<PathBuf>,
    zallet_rpc: Option<SocketAddr>,
    zallet_cookie_file: Option<PathBuf>,
    zcash_node_rpc: SocketAddr,
    zcash_node_cookie_file: PathBuf,
    zcash_signer_journal_directory: Option<PathBuf>,
    zcash_signer_account: Option<Uuid>,
    zcash_signer_account_index: Option<u32>,
    portal_token_pepper_file: PathBuf,
    portal_totp_key_file: PathBuf,
    wcash_policy: RawChainPolicy,
    zcash_policy: RawChainPolicy,
    initial_share_target_be: String,
    easiest_share_target_be: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum RawMiningAuthenticationMode {
    Token,
    UsernameOnly,
}

const fn default_mining_authentication() -> RawMiningAuthenticationMode {
    RawMiningAuthenticationMode::Token
}

impl RuntimeConfig {
    /// Exact wallet network corresponding to this validated deployment.
    pub(crate) fn wallet_network(&self) -> wcash_wec_payout_signer::WalletNetwork {
        match self.network {
            ChainNetwork::Testnet => wcash_wec_payout_signer::WalletNetwork::Testnet,
            ChainNetwork::Mainnet => wcash_wec_payout_signer::WalletNetwork::Mainnet,
            #[cfg(feature = "regtest")]
            ChainNetwork::Regtest => wcash_wec_payout_signer::WalletNetwork::Regtest,
        }
    }

    /// Frozen signature branch for the explicitly selected Wcash environment.
    pub(crate) fn wcash_branch_id(&self) -> &'static str {
        if self.network == ChainNetwork::Mainnet {
            return "d9c6a7ee";
        }
        #[cfg(feature = "regtest")]
        if self.network == ChainNetwork::Regtest {
            return wcash_wec_payout_signer::WCASH_REGTEST_BRANCH_ID;
        }
        wcash_wec_payout_signer::WCASH_TESTNET_BRANCH_ID
    }

    /// Reads one protected, bounded TOML policy without accepting symlinks.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let bytes = read_protected(path, MAX_CONFIG_BYTES, false)?;
        let raw: RawConfig =
            toml::from_str(std::str::from_utf8(&bytes).map_err(|_| ConfigError::InvalidEncoding)?)?;
        Self::try_from(raw)
    }

    /// Reads and validates the PostgreSQL URL without exposing it in diagnostics.
    pub fn database_url(&self) -> Result<Zeroizing<String>, ConfigError> {
        read_utf8_credential(&self.database_url_file)
    }

    /// Reads an exact 256-bit portal secret from a protected binary file.
    pub fn portal_secret(path: &Path) -> Result<Zeroizing<[u8; 32]>, ConfigError> {
        let bytes = read_protected(path, 32, true)?;
        if bytes.len() != 32 {
            return Err(ConfigError::CredentialLength);
        }
        let mut value = Zeroizing::new([0_u8; 32]);
        value.copy_from_slice(&bytes);
        if value.iter().all(|byte| *byte == 0) {
            return Err(ConfigError::WeakCredential);
        }
        Ok(value)
    }
}

impl TryFrom<RawConfig> for RuntimeConfig {
    type Error = ConfigError;

    fn try_from(raw: RawConfig) -> Result<Self, Self::Error> {
        let network = match raw.network.as_str() {
            "testnet" => ChainNetwork::Testnet,
            "mainnet" => ChainNetwork::Mainnet,
            #[cfg(feature = "regtest")]
            "regtest" => ChainNetwork::Regtest,
            _ => return Err(ConfigError::MainnetDisabled),
        };
        let isolated = network.as_str() == "regtest";
        if raw.deployment_id.is_nil()
            || raw.pool_instance.is_nil()
            || raw.backend_instance.is_nil()
            || raw.journal_stream.is_nil()
            || raw.backend_instance == raw.journal_stream
            || raw.chain_id == 0
        {
            return Err(ConfigError::InvalidIdentity);
        }
        require_absolute(&raw.backend_socket)?;
        for path in [
            &raw.database_url_file,
            &raw.wcash_wallet_program,
            &raw.wcash_node_cookie_file,
            &raw.zcash_node_cookie_file,
            &raw.portal_token_pepper_file,
            &raw.portal_totp_key_file,
        ] {
            require_absolute(path)?;
        }
        let automatic_payout = parse_automatic_payout(&raw)?;
        if raw.stratum_listen.port() == 0
            || (raw.stratum_listen.ip().is_loopback() != isolated)
            || raw.stratum_listen.ip().is_multicast()
            || raw.portal_listen.port() == 0
            || !raw.portal_listen.ip().is_loopback()
            || !raw.portal_origin.starts_with("https://")
            || raw.portal_origin.ends_with('/')
            || raw.portal_origin.chars().any(char::is_whitespace)
            || raw.payout_change_hold_secs > 7 * 24 * 60 * 60
            || !(1..=127).contains(&raw.nonce_namespace)
            || !(1..=16_777_216).contains(&raw.nonce_reservation)
            || !(1..=64).contains(&raw.database_connections)
            || !(1..=65_535).contains(&raw.maximum_miners)
            || !(1..=raw.maximum_miners).contains(&raw.maximum_miners_per_ip)
            || !(1..=32).contains(&raw.authentication_parallelism)
            || !raw.wcash_node_rpc.ip().is_loopback()
            || raw.wcash_node_rpc.port() == 0
            || !raw.zcash_node_rpc.ip().is_loopback()
            || raw.zcash_node_rpc.port() == 0
            || raw.wcash_node_rpc == raw.zcash_node_rpc
        {
            return Err(ConfigError::InvalidPolicy);
        }
        let wcash_genesis = decode_hex32("wcash_genesis", &raw.wcash_genesis)?;
        let zcash_genesis = decode_hex32("zcash_genesis", &raw.zcash_genesis)?;
        if network == ChainNetwork::Mainnet {
            let mut child_display = wcash_genesis;
            let mut parent_display = zcash_genesis;
            child_display.reverse();
            parent_display.reverse();
            if hex::encode(child_display) != WCASH_MAINNET_GENESIS
                || hex::encode(parent_display) != ZCASH_MAINNET_GENESIS
                || raw.chain_id != WCASH_AUXILIARY_CHAIN_ID
            {
                return Err(ConfigError::InvalidIdentity);
            }
        }
        #[cfg(feature = "regtest")]
        if isolated {
            let mut child = wcash_genesis;
            let mut parent = zcash_genesis;
            child.reverse();
            parent.reverse();
            if hex::encode(child)
                != "70bf0bab17eff361a6331bb825b3b7253c8c96ff96407f948161d2912658bb1c"
                || hex::encode(parent)
                    != "029f11d80ef9765602235e1bc9727e3eb6ba20839319f761fee920d63401e327"
            {
                return Err(ConfigError::InvalidIdentity);
            }
        }
        let wcash_payout_commitment =
            decode_hex32("wcash_payout_commitment", &raw.wcash_payout_commitment)?;
        let zcash_payout_commitment =
            decode_hex32("zcash_payout_commitment", &raw.zcash_payout_commitment)?;
        let wcash_wallet_sha256 = decode_hex32("wcash_wallet_sha256", &raw.wcash_wallet_sha256)?;
        let initial_share_target_be =
            decode_hex32("initial_share_target_be", &raw.initial_share_target_be)?;
        let easiest_share_target_be =
            decode_hex32("easiest_share_target_be", &raw.easiest_share_target_be)?;
        if [
            wcash_genesis,
            zcash_genesis,
            wcash_payout_commitment,
            zcash_payout_commitment,
            wcash_wallet_sha256,
            initial_share_target_be,
            easiest_share_target_be,
        ]
        .iter()
        .any(|value| value.iter().all(|byte| *byte == 0))
        {
            return Err(ConfigError::InvalidIdentity);
        }
        Ok(Self {
            network,
            deployment_id: raw.deployment_id,
            pool_instance: raw.pool_instance,
            backend_instance: raw.backend_instance,
            journal_stream: raw.journal_stream,
            chain_id: raw.chain_id,
            wcash_genesis,
            zcash_genesis,
            wcash_payout_commitment,
            zcash_payout_commitment,
            backend_socket: raw.backend_socket,
            database_url_file: raw.database_url_file,
            stratum_listen: raw.stratum_listen,
            portal_listen: raw.portal_listen,
            portal_origin: raw.portal_origin,
            registration_open: raw.registration_open,
            payout_change_hold_secs: raw.payout_change_hold_secs,
            nonce_namespace: raw.nonce_namespace,
            nonce_reservation: raw.nonce_reservation,
            database_connections: raw.database_connections,
            maximum_miners: raw.maximum_miners,
            maximum_miners_per_ip: raw.maximum_miners_per_ip,
            authentication_parallelism: raw.authentication_parallelism,
            mining_authentication: match raw.mining_authentication {
                RawMiningAuthenticationMode::Token => MiningAuthenticationMode::Token,
                RawMiningAuthenticationMode::UsernameOnly => MiningAuthenticationMode::UsernameOnly,
            },
            wcash_wallet_program: raw.wcash_wallet_program,
            wcash_wallet_sha256,
            wcash_wallet_uid: raw.wcash_wallet_uid,
            payout_mode: raw.payout_mode,
            automatic_payout,
            wcash_node_rpc: raw.wcash_node_rpc,
            wcash_node_cookie_file: raw.wcash_node_cookie_file,
            zcash_node_rpc: raw.zcash_node_rpc,
            zcash_node_cookie_file: raw.zcash_node_cookie_file,
            portal_token_pepper_file: raw.portal_token_pepper_file,
            portal_totp_key_file: raw.portal_totp_key_file,
            wcash_policy: parse_chain_policy(raw.wcash_policy)?,
            zcash_policy: parse_chain_policy(raw.zcash_policy)?,
            initial_share_target_be,
            easiest_share_target_be,
        })
    }
}

fn parse_automatic_payout(raw: &RawConfig) -> Result<Option<AutomaticPayoutConfig>, ConfigError> {
    let wcash_fields_present = [
        raw.wcash_wallet_database.is_some(),
        raw.wcash_lightwalletd_endpoint.is_some(),
        raw.wcash_wallet_sync_batch_size.is_some(),
        raw.wcash_wallet_sync_timeout_seconds.is_some(),
        raw.wcash_wallet_seed_file.is_some(),
        raw.wcash_seed_uid.is_some(),
        raw.wcash_signer_journal_directory.is_some(),
        raw.wcash_signer_account.is_some(),
    ];
    let zcash_fields_present = [
        raw.zallet_configuration.is_some(),
        raw.zallet_rpc.is_some(),
        raw.zallet_cookie_file.is_some(),
        raw.zcash_signer_journal_directory.is_some(),
        raw.zcash_signer_account.is_some(),
        raw.zcash_signer_account_index.is_some(),
    ];
    match raw.payout_mode {
        PayoutMode::Deferred => {
            if wcash_fields_present.into_iter().any(|present| present)
                || zcash_fields_present.into_iter().any(|present| present)
                || !raw.automatic_payout_chains.is_empty()
                || raw.wcash_opening_pool_equity_zat != 0
            {
                return Err(ConfigError::InvalidPolicy);
            }
            Ok(None)
        }
        PayoutMode::Automatic => {
            if raw.automatic_payout_chains.as_slice() != [AutomaticPayoutChain::Wcash]
                || wcash_fields_present.into_iter().any(|present| !present)
                || zcash_fields_present.into_iter().any(|present| present)
            {
                return Err(ConfigError::InvalidPolicy);
            }
            let config = AutomaticPayoutConfig {
                chains: raw.automatic_payout_chains.clone(),
                wcash_wallet_database: raw
                    .wcash_wallet_database
                    .clone()
                    .ok_or(ConfigError::InvalidPolicy)?,
                wcash_lightwalletd_endpoint: raw
                    .wcash_lightwalletd_endpoint
                    .clone()
                    .ok_or(ConfigError::InvalidPolicy)?,
                wcash_wallet_sync_batch_size: raw
                    .wcash_wallet_sync_batch_size
                    .ok_or(ConfigError::InvalidPolicy)?,
                wcash_wallet_sync_timeout: Duration::from_secs(
                    raw.wcash_wallet_sync_timeout_seconds
                        .ok_or(ConfigError::InvalidPolicy)?,
                ),
                wcash_wallet_seed_file: raw
                    .wcash_wallet_seed_file
                    .clone()
                    .ok_or(ConfigError::InvalidPolicy)?,
                wcash_seed_uid: raw.wcash_seed_uid.ok_or(ConfigError::InvalidPolicy)?,
                wcash_signer_journal_directory: raw
                    .wcash_signer_journal_directory
                    .clone()
                    .ok_or(ConfigError::InvalidPolicy)?,
                wcash_signer_account: raw.wcash_signer_account.ok_or(ConfigError::InvalidPolicy)?,
                wcash_opening_pool_equity_zat: raw.wcash_opening_pool_equity_zat,
            };
            for path in [
                &config.wcash_wallet_database,
                &config.wcash_wallet_seed_file,
                &config.wcash_signer_journal_directory,
            ] {
                require_absolute(path)?;
            }
            if config.wcash_lightwalletd_endpoint.is_empty()
                || config
                    .wcash_lightwalletd_endpoint
                    .chars()
                    .any(char::is_whitespace)
                || !(1..=16).contains(&config.wcash_wallet_sync_batch_size)
                || config.wcash_wallet_sync_timeout.is_zero()
                || config.wcash_wallet_sync_timeout > MAX_WCASH_WALLET_SYNC_TIMEOUT
            {
                return Err(ConfigError::InvalidPolicy);
            }
            if config.wcash_signer_account.is_nil() {
                return Err(ConfigError::InvalidIdentity);
            }
            Ok(Some(config))
        }
    }
}

fn parse_chain_policy(raw: RawChainPolicy) -> Result<ChainRuntimePolicy, ConfigError> {
    let pplns_window_work =
        BigUint::from_str(&raw.pplns_window_work).map_err(|_| ConfigError::InvalidPolicy)?;
    if pplns_window_work == BigUint::default()
        || raw.payout_threshold_zat == 0
        || !(100..=1_000_000).contains(&raw.required_confirmations)
        || !(1..=200).contains(&raw.maximum_payout_outputs)
        || raw.maximum_payout_zat == 0
        || raw.maximum_network_fee_zat == 0
        || !(1..=1_000).contains(&raw.maximum_network_fee_bps)
        || raw.policy_version == 0
    {
        return Err(ConfigError::InvalidPolicy);
    }
    Ok(ChainRuntimePolicy {
        pplns_window_work,
        payout_threshold_zat: raw.payout_threshold_zat,
        required_confirmations: raw.required_confirmations,
        maximum_payout_outputs: raw.maximum_payout_outputs,
        maximum_payout_zat: raw.maximum_payout_zat,
        maximum_network_fee_zat: raw.maximum_network_fee_zat,
        maximum_network_fee_bps: raw.maximum_network_fee_bps,
        policy_version: raw.policy_version,
    })
}

fn decode_hex32(field: &'static str, value: &str) -> Result<[u8; 32], ConfigError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ConfigError::InvalidHex(field));
    }
    let decoded = hex::decode(value).map_err(|_| ConfigError::InvalidHex(field))?;
    decoded
        .try_into()
        .map_err(|_| ConfigError::InvalidHex(field))
}

fn require_absolute(path: &Path) -> Result<(), ConfigError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(ConfigError::UnsafePath);
    }
    Ok(())
}

fn read_utf8_credential(path: &Path) -> Result<Zeroizing<String>, ConfigError> {
    let bytes = read_protected(path, MAX_CREDENTIAL_BYTES, true)?;
    let value = std::str::from_utf8(&bytes).map_err(|_| ConfigError::InvalidEncoding)?;
    let value = value.trim_end_matches(['\r', '\n']);
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(ConfigError::InvalidCredential);
    }
    Ok(Zeroizing::new(value.to_owned()))
}

pub(crate) fn read_protected(
    path: &Path,
    maximum: u64,
    secret: bool,
) -> Result<Zeroizing<Vec<u8>>, ConfigError> {
    require_absolute(path)?;
    let trusted_uid = geteuid().as_raw();
    let parent = open_protected_parent(path, trusted_uid)?;
    let leaf = path.file_name().ok_or(ConfigError::UnsafePath)?;
    let before =
        statat(&parent, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| ConfigError::Unavailable)?;
    validate_leaf(&before, maximum, secret, trusted_uid)?;

    let descriptor = openat(
        &parent,
        leaf,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| ConfigError::UnsafeFile)?;
    let opened = fstat(&descriptor).map_err(|_| ConfigError::Unavailable)?;
    validate_leaf(&opened, maximum, secret, trusted_uid)?;
    if !same_security_metadata(&before, &opened) {
        return Err(ConfigError::UnsafeFile);
    }

    let file = File::from(descriptor);
    let mut bytes = Zeroizing::new(Vec::new());
    let mut bounded = (&file).take(maximum.saturating_add(1));
    bounded
        .read_to_end(&mut bytes)
        .map_err(|_| ConfigError::Unavailable)?;
    if bytes.len() as u64 > maximum {
        return Err(ConfigError::UnsafeFile);
    }

    let after = fstat(&file).map_err(|_| ConfigError::Unavailable)?;
    validate_leaf(&after, maximum, secret, trusted_uid)?;
    if !same_security_metadata(&opened, &after) || after.st_size != bytes.len() as i64 {
        return Err(ConfigError::UnsafeFile);
    }
    Ok(bytes)
}

fn open_protected_parent(path: &Path, trusted_uid: u32) -> Result<File, ConfigError> {
    let parent = path.parent().ok_or(ConfigError::UnsafePath)?;
    let root = openat(
        CWD,
        Path::new("/"),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| ConfigError::Unavailable)?;
    validate_parent(
        &fstat(&root).map_err(|_| ConfigError::Unavailable)?,
        trusted_uid,
    )?;
    let mut directory = File::from(root);

    for component in parent.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = open_protected_directory(&directory, name, trusted_uid)?;
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(ConfigError::UnsafePath);
            }
        }
    }
    Ok(directory)
}

fn open_protected_directory(
    parent: &File,
    name: &OsStr,
    trusted_uid: u32,
) -> Result<File, ConfigError> {
    let descriptor = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| ConfigError::UnsafeFile)?;
    validate_parent(
        &fstat(&descriptor).map_err(|_| ConfigError::Unavailable)?,
        trusted_uid,
    )?;
    Ok(File::from(descriptor))
}

fn validate_parent(metadata: &Stat, trusted_uid: u32) -> Result<(), ConfigError> {
    if !FileType::from_raw_mode(metadata.st_mode).is_dir()
        || !is_trusted_owner(metadata.st_uid, trusted_uid)
        || metadata.st_mode & 0o022 != 0
    {
        return Err(ConfigError::UnsafeFile);
    }
    Ok(())
}

fn validate_leaf(
    metadata: &Stat,
    maximum: u64,
    secret: bool,
    trusted_uid: u32,
) -> Result<(), ConfigError> {
    let forbidden = if secret { 0o077 } else { 0o022 };
    if !FileType::from_raw_mode(metadata.st_mode).is_file()
        || metadata.st_nlink != 1
        || !is_trusted_owner(metadata.st_uid, trusted_uid)
        || metadata.st_mode & forbidden != 0
        || metadata.st_size < 0
        || metadata.st_size as u64 > maximum
    {
        return Err(ConfigError::UnsafeFile);
    }
    Ok(())
}

fn same_security_metadata(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_mode == right.st_mode
        && left.st_nlink == right.st_nlink
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

fn is_trusted_owner(owner_uid: u32, service_uid: u32) -> bool {
    owner_uid == 0 || owner_uid == service_uid
}

/// Configuration failure with no credential contents in its display text.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The policy file or credential could not be opened.
    #[error("configuration input is unavailable")]
    Unavailable,
    /// File type, size, link count, or permissions were unsafe.
    #[error("configuration input does not satisfy protected-file policy")]
    UnsafeFile,
    /// A configured path was not absolute and normalized.
    #[error("configuration paths must be absolute and normalized")]
    UnsafePath,
    /// TOML syntax or shape was invalid.
    #[error("configuration syntax is invalid: {0}")]
    Toml(#[from] toml::de::Error),
    /// Input was not UTF-8.
    #[error("configuration input encoding is invalid")]
    InvalidEncoding,
    /// A named 256-bit value was not canonical hexadecimal.
    #[error("configuration field {0} must contain exactly 32 hexadecimal bytes")]
    InvalidHex(&'static str),
    /// Testnet-only release was asked to enter Mainnet.
    #[error("mainnet serving is disabled in this release")]
    MainnetDisabled,
    /// A stable network or process identity was empty or collapsed.
    #[error("deployment identity is invalid")]
    InvalidIdentity,
    /// A listener or bounded runtime policy was invalid.
    #[error("runtime policy is invalid")]
    InvalidPolicy,
    /// Credential was not the required exact byte length.
    #[error("credential has an invalid length")]
    CredentialLength,
    /// Secret was all zero.
    #[error("credential is cryptographically weak")]
    WeakCredential,
    /// Text credential was empty or contained control characters.
    #[error("credential has an invalid representation")]
    InvalidCredential,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::{fs, io::Write};

    #[cfg(unix)]
    use std::os::unix::fs::{symlink, PermissionsExt};
    use tempfile::TempDir;

    use super::*;

    fn write_file(directory: &TempDir, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
        let path = protected_root(directory).join(name);
        write_path(&path, bytes, mode);
        path
    }

    fn write_path(path: &Path, bytes: &[u8], mode: u32) {
        let mut file = File::create(path).expect("fixture file");
        file.write_all(bytes).expect("fixture write");
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("fixture permissions");
    }

    fn protected_root(directory: &TempDir) -> PathBuf {
        fs::canonicalize(directory.path()).expect("canonical fixture root")
    }

    fn fixture(directory: &TempDir, network: &str) -> String {
        format!(
            r#"network = "{network}"
deployment_id = "11111111-1111-4111-8111-111111111111"
pool_instance = "22222222-2222-4222-8222-222222222222"
backend_instance = "33333333-3333-4333-8333-333333333333"
journal_stream = "44444444-4444-4444-8444-444444444444"
chain_id = 1991772603
wcash_genesis = "{one}"
zcash_genesis = "{two}"
wcash_payout_commitment = "{three}"
zcash_payout_commitment = "{four}"
backend_socket = "/run/zecwec/backend.sock"
database_url_file = "{root}/database"
stratum_listen = "0.0.0.0:28237"
portal_listen = "127.0.0.1:8080"
portal_origin = "https://testnet.zecwec.com"
payout_change_hold_secs = 172800
nonce_namespace = 1
nonce_reservation = 1000000
database_connections = 8
maximum_miners = 1024
maximum_miners_per_ip = 8
authentication_parallelism = 4
wcash_wallet_program = "/opt/wcash/bin/wcash-wallet"
wcash_wallet_sha256 = "{five}"
wcash_wallet_uid = 0
payout_mode = "automatic"
automatic_payout_chains = ["wcash"]
wcash_wallet_database = "/var/lib/zecwec/wcash-wallet.sqlite"
wcash_lightwalletd_endpoint = "http://127.0.0.1:38234"
wcash_wallet_sync_batch_size = 16
wcash_wallet_sync_timeout_seconds = 300
wcash_node_rpc = "127.0.0.1:38232"
wcash_node_cookie_file = "{root}/wcash-node.cookie"
wcash_wallet_seed_file = "{root}/wcash-seed"
wcash_seed_uid = 0
wcash_signer_journal_directory = "/var/lib/zecwec/wec-payout-journal"
wcash_signer_account = "55555555-5555-4555-8555-555555555555"
zcash_node_rpc = "127.0.0.1:18242"
zcash_node_cookie_file = "{root}/zebra.cookie"
portal_token_pepper_file = "{root}/pepper"
portal_totp_key_file = "{root}/totp"
initial_share_target_be = "{six}"
easiest_share_target_be = "{seven}"

[wcash_policy]
pplns_window_work = "1000000"
payout_threshold_zat = 100000000
required_confirmations = 100
maximum_payout_outputs = 50
maximum_payout_zat = 100000000
maximum_network_fee_zat = 1000000
maximum_network_fee_bps = 100
policy_version = 1

[zcash_policy]
pplns_window_work = "1000000"
payout_threshold_zat = 100000000
required_confirmations = 100
maximum_payout_outputs = 50
maximum_payout_zat = 100000000
maximum_network_fee_zat = 1000000
maximum_network_fee_bps = 100
policy_version = 1
"#,
            root = protected_root(directory).display(),
            one = "01".repeat(32),
            two = "02".repeat(32),
            three = "03".repeat(32),
            four = "04".repeat(32),
            five = "05".repeat(32),
            six = "06".repeat(32),
            seven = "07".repeat(32),
        )
    }

    fn deferred_fixture(directory: &TempDir) -> String {
        let root = protected_root(directory);
        let mut config = fixture(directory, "testnet")
            .replace("payout_mode = \"automatic\"", "payout_mode = \"deferred\"");
        for line in [
            "automatic_payout_chains = [\"wcash\"]\n".to_owned(),
            "wcash_wallet_database = \"/var/lib/zecwec/wcash-wallet.sqlite\"\n".to_owned(),
            "wcash_lightwalletd_endpoint = \"http://127.0.0.1:38234\"\n".to_owned(),
            "wcash_wallet_sync_batch_size = 16\n".to_owned(),
            "wcash_wallet_sync_timeout_seconds = 300\n".to_owned(),
            format!(
                "wcash_wallet_seed_file = \"{}/wcash-seed\"\n",
                root.display()
            ),
            "wcash_seed_uid = 0\n".to_owned(),
            "wcash_signer_journal_directory = \"/var/lib/zecwec/wec-payout-journal\"\n".to_owned(),
            "wcash_signer_account = \"55555555-5555-4555-8555-555555555555\"\n".to_owned(),
        ] {
            config = config.replace(&line, "");
        }
        config
    }

    #[test]
    fn exact_testnet_policy_loads_and_credentials_remain_separate() {
        let directory = TempDir::new().expect("temp dir");
        let config_path = write_file(
            &directory,
            "pool.toml",
            fixture(&directory, "testnet").as_bytes(),
            0o600,
        );
        write_file(
            &directory,
            "database",
            b"postgresql://pool@/zecwec\n",
            0o600,
        );
        write_file(&directory, "pepper", &[7; 32], 0o600);
        write_file(&directory, "totp", &[8; 32], 0o600);
        let config = RuntimeConfig::load(&config_path).expect("valid config");
        assert_eq!(config.nonce_namespace, 1);
        assert_eq!(
            config.mining_authentication,
            MiningAuthenticationMode::Token
        );
        assert_eq!(
            config.database_url().expect("url").as_str(),
            "postgresql://pool@/zecwec"
        );
        assert_eq!(
            *RuntimeConfig::portal_secret(&config.portal_token_pepper_file).expect("secret"),
            [7; 32]
        );
    }

    #[test]
    fn username_only_mining_authentication_is_explicit() {
        let directory = TempDir::new().expect("temp dir");
        let policy = fixture(&directory, "testnet").replace(
            "authentication_parallelism = 4",
            "authentication_parallelism = 4\nmining_authentication = \"username_only\"",
        );
        let path = write_file(&directory, "pool.toml", policy.as_bytes(), 0o600);
        let loaded = RuntimeConfig::load(&path).expect("username-only policy loads");
        assert_eq!(
            loaded.mining_authentication,
            MiningAuthenticationMode::UsernameOnly
        );
    }

    #[test]
    fn deferred_mining_policy_contains_no_spending_runtime_inputs() {
        let directory = TempDir::new().expect("temp dir");
        let config_path = write_file(
            &directory,
            "pool-deferred.toml",
            deferred_fixture(&directory).as_bytes(),
            0o600,
        );
        let config = RuntimeConfig::load(&config_path).expect("valid deferred config");
        assert_eq!(config.payout_mode, PayoutMode::Deferred);
        assert!(config.automatic_payout.is_none());

        let contaminated = write_file(
            &directory,
            "pool-deferred-contaminated.toml",
            deferred_fixture(&directory)
                .replace(
                    "\n[wcash_policy]",
                    "\nzallet_rpc = \"127.0.0.1:28232\"\n\n[wcash_policy]",
                )
                .as_bytes(),
            0o600,
        );
        assert!(matches!(
            RuntimeConfig::load(&contaminated),
            Err(ConfigError::InvalidPolicy)
        ));
    }

    #[test]
    fn mainnet_deferred_payout_uses_mainnet_branch() {
        let directory = TempDir::new().expect("temp dir");
        let wire = |display: &str| {
            let mut bytes = hex::decode(display).expect("genesis hex");
            bytes.reverse();
            hex::encode(bytes)
        };
        let mainnet = deferred_fixture(&directory)
            .replace("network = \"testnet\"", "network = \"mainnet\"")
            .replace("chain_id = 1991772603", "chain_id = 1464025427")
            .replace(&"01".repeat(32), &wire(WCASH_MAINNET_GENESIS))
            .replace(&"02".repeat(32), &wire(ZCASH_MAINNET_GENESIS));
        let path = write_file(
            &directory,
            "mainnet-deferred.toml",
            mainnet.as_bytes(),
            0o600,
        );
        let loaded = RuntimeConfig::load(&path).expect("mainnet accounting-only policy");
        assert_eq!(loaded.network, ChainNetwork::Mainnet);
        assert_eq!(loaded.payout_mode, PayoutMode::Deferred);
        assert!(!loaded.registration_open);
        assert_eq!(loaded.wcash_branch_id(), "d9c6a7ee");

        let open = mainnet.replace(
            "\n[wcash_policy]",
            "\nregistration_open = true\n\n[wcash_policy]",
        );
        write_path(&path, open.as_bytes(), 0o600);
        assert!(
            RuntimeConfig::load(&path)
                .expect("explicit registration gate")
                .registration_open
        );

        let wrong_genesis = mainnet.replace(&wire(WCASH_MAINNET_GENESIS), &"01".repeat(32));
        write_path(&path, wrong_genesis.as_bytes(), 0o600);
        assert!(matches!(
            RuntimeConfig::load(&path),
            Err(ConfigError::InvalidIdentity)
        ));

        let wrong_chain_id = mainnet.replace("chain_id = 1464025427", "chain_id = 1");
        write_path(&path, wrong_chain_id.as_bytes(), 0o600);
        assert!(matches!(
            RuntimeConfig::load(&path),
            Err(ConfigError::InvalidIdentity)
        ));
    }

    #[test]
    fn mainnet_accepts_explicit_wcash_only_automatic_payout() {
        let directory = TempDir::new().expect("temp dir");
        let wire = |display: &str| {
            let mut bytes = hex::decode(display).expect("genesis hex");
            bytes.reverse();
            hex::encode(bytes)
        };
        let mainnet = fixture(&directory, "testnet")
            .replace("network = \"testnet\"", "network = \"mainnet\"")
            .replace("chain_id = 1991772603", "chain_id = 1464025427")
            .replace(&"01".repeat(32), &wire(WCASH_MAINNET_GENESIS))
            .replace(&"02".repeat(32), &wire(ZCASH_MAINNET_GENESIS))
            .replace(
                "payout_change_hold_secs = 172800",
                "payout_change_hold_secs = 0\nwcash_opening_pool_equity_zat = 123",
            );
        let path = write_file(
            &directory,
            "mainnet-wcash-payout.toml",
            mainnet.as_bytes(),
            0o600,
        );
        let loaded = RuntimeConfig::load(&path).expect("Mainnet Wcash payout policy");
        let payout = loaded
            .automatic_payout
            .expect("automatic Wcash payout configuration");
        assert_eq!(loaded.network, ChainNetwork::Mainnet);
        assert_eq!(loaded.payout_change_hold_secs, 0);
        assert_eq!(payout.chains, vec![AutomaticPayoutChain::Wcash]);
        assert_eq!(payout.wcash_opening_pool_equity_zat, 123);
    }

    #[test]
    fn regtest_configuration_is_feature_gated_and_chain_pinned() {
        let directory = TempDir::new().expect("temp dir");
        let fixture = fixture(&directory, "regtest").replace("0.0.0.0:28237", "127.0.0.1:28237");
        let path = write_file(&directory, "regtest.toml", fixture.as_bytes(), 0o600);
        #[cfg(not(feature = "regtest"))]
        assert!(matches!(
            RuntimeConfig::load(&path),
            Err(ConfigError::MainnetDisabled)
        ));
        #[cfg(feature = "regtest")]
        {
            assert!(matches!(
                RuntimeConfig::load(&path),
                Err(ConfigError::InvalidIdentity)
            ));
            let child = "70bf0bab17eff361a6331bb825b3b7253c8c96ff96407f948161d2912658bb1c";
            let parent = "029f11d80ef9765602235e1bc9727e3eb6ba20839319f761fee920d63401e327";
            let wire = |display: &str| {
                let mut bytes = hex::decode(display).expect("genesis hex");
                bytes.reverse();
                hex::encode(bytes)
            };
            let fixture = fixture
                .replace(&"01".repeat(32), &wire(child))
                .replace(&"02".repeat(32), &wire(parent));
            write_path(&path, fixture.as_bytes(), 0o600);
            assert_eq!(
                RuntimeConfig::load(&path).expect("isolated policy").network,
                ChainNetwork::Regtest
            );
            write_path(
                &path,
                fixture
                    .replace("127.0.0.1:28237", "0.0.0.0:28237")
                    .as_bytes(),
                0o600,
            );
            assert!(matches!(
                RuntimeConfig::load(&path),
                Err(ConfigError::InvalidPolicy)
            ));
        }
    }

    #[test]
    fn mainnet_identity_unknown_fields_and_weak_files_fail_closed() {
        let directory = TempDir::new().expect("temp dir");
        let mainnet = write_file(
            &directory,
            "mainnet.toml",
            fixture(&directory, "mainnet").as_bytes(),
            0o600,
        );
        assert!(matches!(
            RuntimeConfig::load(&mainnet),
            Err(ConfigError::InvalidIdentity)
        ));

        let unknown = write_file(
            &directory,
            "unknown.toml",
            format!("{}unexpected = true\n", fixture(&directory, "testnet")).as_bytes(),
            0o600,
        );
        assert!(matches!(
            RuntimeConfig::load(&unknown),
            Err(ConfigError::Toml(_))
        ));

        let secret = write_file(&directory, "secret", &[0; 32], 0o644);
        assert!(matches!(
            RuntimeConfig::portal_secret(&secret),
            Err(ConfigError::UnsafeFile)
        ));
    }

    #[test]
    fn wcash_validator_endpoint_and_cookie_are_mandatory_and_loopback_only() {
        let directory = TempDir::new().expect("temp dir");
        let valid = fixture(&directory, "testnet");

        let missing_endpoint = write_file(
            &directory,
            "missing-endpoint.toml",
            valid
                .replace("wcash_node_rpc = \"127.0.0.1:38232\"\n", "")
                .as_bytes(),
            0o600,
        );
        assert!(matches!(
            RuntimeConfig::load(&missing_endpoint),
            Err(ConfigError::Toml(_))
        ));

        let missing_cookie = write_file(
            &directory,
            "missing-cookie.toml",
            valid
                .replace(
                    &format!(
                        "wcash_node_cookie_file = \"{}/wcash-node.cookie\"\n",
                        protected_root(&directory).display()
                    ),
                    "",
                )
                .as_bytes(),
            0o600,
        );
        assert!(matches!(
            RuntimeConfig::load(&missing_cookie),
            Err(ConfigError::Toml(_))
        ));

        let public_endpoint = write_file(
            &directory,
            "public-validator.toml",
            valid
                .replace(
                    "wcash_node_rpc = \"127.0.0.1:38232\"",
                    "wcash_node_rpc = \"198.51.100.8:38232\"",
                )
                .as_bytes(),
            0o600,
        );
        assert!(matches!(
            RuntimeConfig::load(&public_endpoint),
            Err(ConfigError::InvalidPolicy)
        ));
    }

    #[test]
    fn wcash_seedless_sync_policy_is_explicit_and_bounded() {
        let directory = TempDir::new().expect("temp dir");
        let valid = fixture(&directory, "testnet");

        let missing = write_file(
            &directory,
            "missing-sync-timeout.toml",
            valid
                .replace("wcash_wallet_sync_timeout_seconds = 300\n", "")
                .as_bytes(),
            0o600,
        );
        assert!(matches!(
            RuntimeConfig::load(&missing),
            Err(ConfigError::InvalidPolicy)
        ));

        for (name, from, to) in [
            (
                "zero-sync-batch.toml",
                "wcash_wallet_sync_batch_size = 16",
                "wcash_wallet_sync_batch_size = 0",
            ),
            (
                "oversized-sync-batch.toml",
                "wcash_wallet_sync_batch_size = 16",
                "wcash_wallet_sync_batch_size = 17",
            ),
            (
                "zero-sync-timeout.toml",
                "wcash_wallet_sync_timeout_seconds = 300",
                "wcash_wallet_sync_timeout_seconds = 0",
            ),
            (
                "unbounded-sync-timeout.toml",
                "wcash_wallet_sync_timeout_seconds = 300",
                "wcash_wallet_sync_timeout_seconds = 901",
            ),
        ] {
            let path = write_file(&directory, name, valid.replace(from, to).as_bytes(), 0o600);
            assert!(matches!(
                RuntimeConfig::load(&path),
                Err(ConfigError::InvalidPolicy)
            ));
        }
    }

    #[test]
    fn leaf_and_parent_symlinks_fail_closed() {
        let directory = TempDir::new().expect("temp dir");
        let root = protected_root(&directory);
        let secret = write_file(&directory, "secret", &[7; 32], 0o600);
        let leaf_link = root.join("secret-link");
        symlink(&secret, &leaf_link).expect("leaf symlink");
        assert!(matches!(
            RuntimeConfig::portal_secret(&leaf_link),
            Err(ConfigError::UnsafeFile)
        ));

        let real_parent = root.join("real-parent");
        fs::create_dir(&real_parent).expect("real parent");
        fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o700))
            .expect("real parent permissions");
        write_path(&real_parent.join("nested-secret"), &[8; 32], 0o600);
        let parent_link = root.join("parent-link");
        symlink(&real_parent, &parent_link).expect("parent symlink");
        assert!(matches!(
            RuntimeConfig::portal_secret(&parent_link.join("nested-secret")),
            Err(ConfigError::UnsafeFile)
        ));
    }

    #[test]
    fn writable_parent_and_hardlinked_leaf_fail_closed() {
        let directory = TempDir::new().expect("temp dir");
        let root = protected_root(&directory);
        let writable_parent = root.join("writable-parent");
        fs::create_dir(&writable_parent).expect("writable parent");
        write_path(&writable_parent.join("secret"), &[7; 32], 0o600);
        fs::set_permissions(&writable_parent, fs::Permissions::from_mode(0o777))
            .expect("unsafe parent permissions");
        assert!(matches!(
            RuntimeConfig::portal_secret(&writable_parent.join("secret")),
            Err(ConfigError::UnsafeFile)
        ));

        let original = write_file(&directory, "hardlink-source", &[8; 32], 0o600);
        let linked = root.join("hardlink-target");
        fs::hard_link(&original, &linked).expect("hard link");
        assert!(matches!(
            RuntimeConfig::portal_secret(&original),
            Err(ConfigError::UnsafeFile)
        ));
        assert!(matches!(
            RuntimeConfig::portal_secret(&linked),
            Err(ConfigError::UnsafeFile)
        ));
    }

    #[test]
    fn opened_descriptor_metadata_is_revalidated() {
        let directory = TempDir::new().expect("temp dir");
        let secret = write_file(&directory, "metadata-secret", &[9; 32], 0o600);
        let file = File::open(&secret).expect("open fixture");
        let before = fstat(&file).expect("initial metadata");
        validate_leaf(&before, 32, true, geteuid().as_raw()).expect("initially protected");

        fs::set_permissions(&secret, fs::Permissions::from_mode(0o644))
            .expect("weaken permissions");
        let after = fstat(&file).expect("changed metadata");
        assert!(matches!(
            validate_leaf(&after, 32, true, geteuid().as_raw()),
            Err(ConfigError::UnsafeFile)
        ));
        assert!(!same_security_metadata(&before, &after));
    }

    #[test]
    fn only_root_or_effective_service_uid_is_trusted() {
        let service_uid = geteuid().as_raw();
        let foreign_uid = if service_uid == 1 { 2 } else { 1 };
        assert!(is_trusted_owner(0, service_uid));
        assert!(is_trusted_owner(service_uid, service_uid));
        assert!(!is_trusted_owner(foreign_uid, service_uid));

        let directory = TempDir::new().expect("temp dir");
        let secret = write_file(&directory, "foreign-owner", &[9; 32], 0o600);
        let file = File::open(secret).expect("open fixture");
        let mut foreign_leaf = fstat(&file).expect("leaf metadata");
        foreign_leaf.st_uid = foreign_uid;
        assert!(matches!(
            validate_leaf(&foreign_leaf, 32, true, service_uid),
            Err(ConfigError::UnsafeFile)
        ));

        let mut foreign_parent = fstat(
            open_protected_parent(&protected_root(&directory).join("x"), service_uid)
                .expect("protected parent"),
        )
        .expect("parent metadata");
        foreign_parent.st_uid = foreign_uid;
        assert!(matches!(
            validate_parent(&foreign_parent, service_uid),
            Err(ConfigError::UnsafeFile)
        ));
    }
}
