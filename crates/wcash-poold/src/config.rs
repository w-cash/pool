//! Strict, Testnet-only daemon configuration and protected credential loading.

use std::{
    fs::{self, File},
    io::{Read, Take},
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    str::FromStr,
};

use num_bigint::BigUint;
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_CONFIG_BYTES: u64 = 128 * 1024;
const MAX_CREDENTIAL_BYTES: u64 = 16 * 1024;

/// Fully decoded, immutable Testnet service policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeConfig {
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
    /// Integrity-pinned Wolf address command.
    pub wcash_wallet_program: PathBuf,
    /// Expected executable digest.
    pub wcash_wallet_sha256: [u8; 32],
    /// Required executable owner.
    pub wcash_wallet_uid: u32,
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
    nonce_namespace: u8,
    nonce_reservation: u64,
    database_connections: u32,
    maximum_miners: usize,
    maximum_miners_per_ip: usize,
    authentication_parallelism: usize,
    wcash_wallet_program: PathBuf,
    wcash_wallet_sha256: String,
    wcash_wallet_uid: u32,
    portal_token_pepper_file: PathBuf,
    portal_totp_key_file: PathBuf,
    wcash_policy: RawChainPolicy,
    zcash_policy: RawChainPolicy,
    initial_share_target_be: String,
    easiest_share_target_be: String,
}

impl RuntimeConfig {
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
        let bytes = Zeroizing::new(read_protected(path, 32, true)?);
        let value: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| ConfigError::CredentialLength)?;
        if value.iter().all(|byte| *byte == 0) {
            return Err(ConfigError::WeakCredential);
        }
        Ok(Zeroizing::new(value))
    }
}

impl TryFrom<RawConfig> for RuntimeConfig {
    type Error = ConfigError;

    fn try_from(raw: RawConfig) -> Result<Self, Self::Error> {
        if raw.network != "testnet" {
            return Err(ConfigError::MainnetDisabled);
        }
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
            &raw.portal_token_pepper_file,
            &raw.portal_totp_key_file,
        ] {
            require_absolute(path)?;
        }
        if raw.stratum_listen.port() == 0
            || raw.stratum_listen.ip().is_loopback()
            || raw.stratum_listen.ip().is_multicast()
            || raw.portal_listen.port() == 0
            || !raw.portal_listen.ip().is_loopback()
            || !raw.portal_origin.starts_with("https://")
            || raw.portal_origin.ends_with('/')
            || raw.portal_origin.chars().any(char::is_whitespace)
            || !(1..=127).contains(&raw.nonce_namespace)
            || !(1..=16_777_216).contains(&raw.nonce_reservation)
            || !(1..=64).contains(&raw.database_connections)
            || !(1..=65_535).contains(&raw.maximum_miners)
            || !(1..=raw.maximum_miners).contains(&raw.maximum_miners_per_ip)
            || !(1..=32).contains(&raw.authentication_parallelism)
        {
            return Err(ConfigError::InvalidPolicy);
        }
        let wcash_genesis = decode_hex32("wcash_genesis", &raw.wcash_genesis)?;
        let zcash_genesis = decode_hex32("zcash_genesis", &raw.zcash_genesis)?;
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
            nonce_namespace: raw.nonce_namespace,
            nonce_reservation: raw.nonce_reservation,
            database_connections: raw.database_connections,
            maximum_miners: raw.maximum_miners,
            maximum_miners_per_ip: raw.maximum_miners_per_ip,
            authentication_parallelism: raw.authentication_parallelism,
            wcash_wallet_program: raw.wcash_wallet_program,
            wcash_wallet_sha256,
            wcash_wallet_uid: raw.wcash_wallet_uid,
            portal_token_pepper_file: raw.portal_token_pepper_file,
            portal_totp_key_file: raw.portal_totp_key_file,
            wcash_policy: parse_chain_policy(raw.wcash_policy)?,
            zcash_policy: parse_chain_policy(raw.zcash_policy)?,
            initial_share_target_be,
            easiest_share_target_be,
        })
    }
}

fn parse_chain_policy(raw: RawChainPolicy) -> Result<ChainRuntimePolicy, ConfigError> {
    let pplns_window_work =
        BigUint::from_str(&raw.pplns_window_work).map_err(|_| ConfigError::InvalidPolicy)?;
    if pplns_window_work == BigUint::default()
        || raw.payout_threshold_zat == 0
        || !(100..=1_000_000).contains(&raw.required_confirmations)
        || !(1..=200).contains(&raw.maximum_payout_outputs)
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
    let bytes = Zeroizing::new(read_protected(path, MAX_CREDENTIAL_BYTES, true)?);
    let value = std::str::from_utf8(&bytes).map_err(|_| ConfigError::InvalidEncoding)?;
    let value = value.trim_end_matches(['\r', '\n']);
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(ConfigError::InvalidCredential);
    }
    Ok(Zeroizing::new(value.to_owned()))
}

fn read_protected(path: &Path, maximum: u64, secret: bool) -> Result<Vec<u8>, ConfigError> {
    require_absolute(path)?;
    let before = fs::symlink_metadata(path).map_err(|_| ConfigError::Unavailable)?;
    if !before.file_type().is_file() || before.file_type().is_symlink() || before.len() > maximum {
        return Err(ConfigError::UnsafeFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let forbidden = if secret { 0o077 } else { 0o022 };
        if before.nlink() != 1 || before.permissions().mode() & forbidden != 0 {
            return Err(ConfigError::UnsafeFile);
        }
    }
    let file = File::open(path).map_err(|_| ConfigError::Unavailable)?;
    let opened = file.metadata().map_err(|_| ConfigError::Unavailable)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(ConfigError::UnsafeFile);
        }
    }
    let mut bytes = Vec::new();
    let mut bounded: Take<File> = file.take(maximum.saturating_add(1));
    bounded
        .read_to_end(&mut bytes)
        .map_err(|_| ConfigError::Unavailable)?;
    if bytes.len() as u64 > maximum {
        return Err(ConfigError::UnsafeFile);
    }
    Ok(bytes)
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
    use std::io::Write;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    use super::*;

    fn write_file(directory: &TempDir, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
        let path = directory.path().join(name);
        let mut file = File::create(&path).expect("fixture file");
        file.write_all(bytes).expect("fixture write");
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("fixture permissions");
        path
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
nonce_namespace = 1
nonce_reservation = 1000000
database_connections = 8
maximum_miners = 1024
maximum_miners_per_ip = 8
authentication_parallelism = 4
wcash_wallet_program = "/opt/wcash/bin/wcash-wallet"
wcash_wallet_sha256 = "{five}"
wcash_wallet_uid = 0
portal_token_pepper_file = "{root}/pepper"
portal_totp_key_file = "{root}/totp"
initial_share_target_be = "{six}"
easiest_share_target_be = "{seven}"

[wcash_policy]
pplns_window_work = "1000000"
payout_threshold_zat = 100000000
required_confirmations = 100
maximum_payout_outputs = 50
maximum_network_fee_zat = 1000000
maximum_network_fee_bps = 100
policy_version = 1

[zcash_policy]
pplns_window_work = "1000000"
payout_threshold_zat = 100000000
required_confirmations = 100
maximum_payout_outputs = 50
maximum_network_fee_zat = 1000000
maximum_network_fee_bps = 100
policy_version = 1
"#,
            root = directory.path().display(),
            one = "01".repeat(32),
            two = "02".repeat(32),
            three = "03".repeat(32),
            four = "04".repeat(32),
            five = "05".repeat(32),
            six = "06".repeat(32),
            seven = "07".repeat(32),
        )
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
            config.database_url().expect("url").as_str(),
            "postgresql://pool@/zecwec"
        );
        assert_eq!(
            *RuntimeConfig::portal_secret(&config.portal_token_pepper_file).expect("secret"),
            [7; 32]
        );
    }

    #[test]
    fn mainnet_unknown_fields_and_weak_files_fail_closed() {
        let directory = TempDir::new().expect("temp dir");
        let mainnet = write_file(
            &directory,
            "mainnet.toml",
            fixture(&directory, "mainnet").as_bytes(),
            0o600,
        );
        assert!(matches!(
            RuntimeConfig::load(&mainnet),
            Err(ConfigError::MainnetDisabled)
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
}
