//! Authoritative payout-address validation for the ZecWec Testnet pool.
//!
//! Zcash addresses are parsed with the protocol crate used by current Zcash
//! software. Wcash addresses use Wolf's own address codec through a fixed,
//! integrity-pinned `wcash-wallet` executable. This keeps Wcash's distinct
//! namespace in one authority instead of duplicating its encoding rules here.

#![forbid(unsafe_code)]

use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use wcash_pool_portal::{
    AddressValidationError, AddressValidator, Asset, ChainNetwork, ReceiverKind,
    ValidatedDestination,
};
use zcash_address::{unified, ConversionError, TryFromAddress, ZcashAddress};
use zcash_protocol::{consensus::NetworkType, PoolType};

const MAX_ADDRESS_BYTES: usize = 512;
const MAX_PROGRAM_BYTES: u64 = 512 * 1024 * 1024;
const MAX_OUTPUT_BYTES: u64 = 16 * 1024;
const MAX_VALIDATION_TIMEOUT: Duration = Duration::from_secs(10);

/// Full Testnet payout-address authority used by the portal.
#[derive(Clone, Debug)]
pub struct TestnetAddressValidator {
    wcash: Arc<WcashCommandValidator>,
}

impl TestnetAddressValidator {
    /// Combines the protected Wolf command with the in-process Zcash parser.
    pub fn new(wcash: WcashCommandValidator) -> Self {
        Self {
            wcash: Arc::new(wcash),
        }
    }

    fn validate_wcash(
        &self,
        candidate: &str,
    ) -> Result<ValidatedDestination, AddressValidationError> {
        match self.wcash.validate_for(WcashNetwork::Testnet, candidate) {
            Ok(validated) => validated.into_portal(candidate),
            Err(CommandValidationError::Rejected) => {
                if parse_supported_zcash(candidate, NetworkType::Test).is_ok() {
                    return Err(AddressValidationError::WrongAsset);
                }
                if self
                    .wcash
                    .validate_for(WcashNetwork::Regtest, candidate)
                    .is_ok()
                {
                    return Err(AddressValidationError::WrongNetwork);
                }
                Err(AddressValidationError::Malformed)
            }
            Err(CommandValidationError::Unavailable) => {
                Err(AddressValidationError::AuthorityUnavailable)
            }
        }
    }

    fn validate_zcash(
        &self,
        candidate: &str,
    ) -> Result<ValidatedDestination, AddressValidationError> {
        match parse_supported_zcash(candidate, NetworkType::Test) {
            Ok(kind) => ValidatedDestination::from_authoritative_validation(
                Asset::Zec,
                ChainNetwork::Testnet,
                canonical_zcash(candidate)?,
                kind,
            ),
            Err(AddressValidationError::Malformed) => {
                match self.wcash.validate_for(WcashNetwork::Testnet, candidate) {
                    Ok(_) => Err(AddressValidationError::WrongAsset),
                    Err(CommandValidationError::Rejected) => Err(AddressValidationError::Malformed),
                    Err(CommandValidationError::Unavailable) => {
                        Err(AddressValidationError::AuthorityUnavailable)
                    }
                }
            }
            Err(error) => Err(error),
        }
    }
}

impl AddressValidator for TestnetAddressValidator {
    fn readiness(
        &self,
        _asset: Asset,
        network: ChainNetwork,
    ) -> Result<(), AddressValidationError> {
        if network != ChainNetwork::Testnet {
            return Err(AddressValidationError::AuthorityUnavailable);
        }
        self.wcash
            .verify_program()
            .map_err(|_| AddressValidationError::AuthorityUnavailable)
    }

    fn validate(
        &self,
        asset: Asset,
        network: ChainNetwork,
        candidate: &str,
    ) -> Result<ValidatedDestination, AddressValidationError> {
        validate_candidate_shape(candidate)?;
        if network != ChainNetwork::Testnet {
            return Err(AddressValidationError::AuthorityUnavailable);
        }
        match asset {
            Asset::Wec => self.validate_wcash(candidate),
            Asset::Zec => self.validate_zcash(candidate),
        }
    }
}

/// Integrity and execution policy for Wolf's Wcash address validator.
pub struct WcashCommandValidator {
    program: PathBuf,
    expected_sha256: [u8; 32],
    trusted_uid: u32,
    timeout: Duration,
}

impl std::fmt::Debug for WcashCommandValidator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WcashCommandValidator")
            .field("program", &self.program)
            .field("expected_sha256", &"[PINNED]")
            .field("trusted_uid", &self.trusted_uid)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl WcashCommandValidator {
    /// Pins one absolute, owner-controlled Wolf wallet executable by SHA-256.
    #[cfg(unix)]
    pub fn new(
        program: impl Into<PathBuf>,
        expected_sha256: [u8; 32],
        trusted_uid: u32,
        timeout: Duration,
    ) -> Result<Self, ValidatorConfigError> {
        let validator = Self {
            program: program.into(),
            expected_sha256,
            trusted_uid,
            timeout,
        };
        validator.validate_config()?;
        validator.verify_program()?;
        Ok(validator)
    }

    #[cfg(unix)]
    fn validate_config(&self) -> Result<(), ValidatorConfigError> {
        if !self.program.is_absolute()
            || self
                .program
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(ValidatorConfigError::ProgramPath);
        }
        if self.expected_sha256.iter().all(|byte| *byte == 0) {
            return Err(ValidatorConfigError::ZeroDigest);
        }
        if self.timeout.is_zero() || self.timeout > MAX_VALIDATION_TIMEOUT {
            return Err(ValidatorConfigError::Timeout);
        }
        Ok(())
    }

    #[cfg(unix)]
    fn verify_program(&self) -> Result<(), ValidatorConfigError> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let metadata = fs::symlink_metadata(&self.program)
            .map_err(|_| ValidatorConfigError::ProgramUnavailable)?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.nlink() != 1
            || metadata.uid() != self.trusted_uid
            || metadata.permissions().mode() & 0o022 != 0
            || metadata.permissions().mode() & 0o111 == 0
            || metadata.len() == 0
            || metadata.len() > MAX_PROGRAM_BYTES
        {
            return Err(ValidatorConfigError::UnsafeProgram);
        }
        let canonical = fs::canonicalize(&self.program)
            .map_err(|_| ValidatorConfigError::ProgramUnavailable)?;
        if canonical != self.program {
            return Err(ValidatorConfigError::ProgramPath);
        }
        let parent = self
            .program
            .parent()
            .ok_or(ValidatorConfigError::ProgramPath)?;
        let parent_metadata =
            fs::symlink_metadata(parent).map_err(|_| ValidatorConfigError::ProgramUnavailable)?;
        let parent_uid = parent_metadata.uid();
        if !parent_metadata.is_dir()
            || parent_metadata.file_type().is_symlink()
            || (parent_uid != 0 && parent_uid != self.trusted_uid)
            || parent_metadata.permissions().mode() & 0o022 != 0
        {
            return Err(ValidatorConfigError::UnsafeProgramDirectory);
        }
        let actual = hash_program(&self.program, metadata.len())?;
        if actual != self.expected_sha256 {
            return Err(ValidatorConfigError::DigestMismatch);
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn verify_program(&self) -> Result<(), ValidatorConfigError> {
        let _ = self;
        Err(ValidatorConfigError::UnsupportedPlatform)
    }

    fn validate_for(
        &self,
        network: WcashNetwork,
        candidate: &str,
    ) -> Result<WcashCommandResponse, CommandValidationError> {
        self.verify_program()
            .map_err(|_| CommandValidationError::Unavailable)?;
        let mut child = Command::new(&self.program)
            .env_clear()
            .current_dir("/")
            .args(["--network", network.as_str(), "validate-address"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| CommandValidationError::Unavailable)?;

        write_candidate(&mut child, candidate)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(CommandValidationError::Unavailable)?;
        let stderr = child
            .stderr
            .take()
            .ok_or(CommandValidationError::Unavailable)?;
        let stdout_reader = spawn_bounded_reader(stdout);
        let stderr_reader = spawn_bounded_reader(stderr);
        let status = wait_bounded(&mut child, self.timeout)?;
        let stdout = join_reader(stdout_reader)?;
        let stderr = join_reader(stderr_reader)?;
        if stdout.exceeded || stderr.exceeded {
            return Err(CommandValidationError::Unavailable);
        }
        if !status.success() {
            return Err(CommandValidationError::Rejected);
        }
        serde_json::from_slice::<WcashCommandResponse>(&stdout.bytes)
            .map_err(|_| CommandValidationError::Unavailable)
    }
}

#[derive(Clone, Copy)]
enum WcashNetwork {
    Testnet,
    Regtest,
}

impl WcashNetwork {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Testnet => "testnet",
            Self::Regtest => "regtest",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WcashCommandResponse {
    network: String,
    receiver_kind: String,
    canonical: String,
}

impl WcashCommandResponse {
    fn into_portal(self, submitted: &str) -> Result<ValidatedDestination, AddressValidationError> {
        if self.network != "testnet" || self.canonical != submitted {
            return Err(AddressValidationError::AuthorityUnavailable);
        }
        let receiver_kind = match self.receiver_kind.as_str() {
            "ironwood" => ReceiverKind::Ironwood,
            "transparent_p2pkh" | "transparent_p2sh" => ReceiverKind::Transparent,
            "tex" => return Err(AddressValidationError::UnsupportedReceiver),
            _ => return Err(AddressValidationError::AuthorityUnavailable),
        };
        ValidatedDestination::from_authoritative_validation(
            Asset::Wec,
            ChainNetwork::Testnet,
            self.canonical,
            receiver_kind,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ZcashReceiverClass {
    Transparent,
    Ironwood,
}

impl TryFromAddress for ZcashReceiverClass {
    type Error = UnsupportedZcashReceiver;

    fn try_from_unified(
        _network: NetworkType,
        address: unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        if address.has_receiver_of_type(PoolType::ORCHARD) {
            Ok(Self::Ironwood)
        } else {
            Err(UnsupportedZcashReceiver.into())
        }
    }

    fn try_from_transparent_p2pkh(
        _network: NetworkType,
        _data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self::Transparent)
    }

    fn try_from_transparent_p2sh(
        _network: NetworkType,
        _data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self::Transparent)
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("unsupported Zcash payout receiver")]
struct UnsupportedZcashReceiver;

fn parse_supported_zcash(
    candidate: &str,
    network: NetworkType,
) -> Result<ReceiverKind, AddressValidationError> {
    let parsed =
        ZcashAddress::try_from_encoded(candidate).map_err(|_| AddressValidationError::Malformed)?;
    let receiver = parsed
        .convert_if_network::<ZcashReceiverClass>(network)
        .map_err(|error| match error {
            ConversionError::IncorrectNetwork { .. } => AddressValidationError::WrongNetwork,
            ConversionError::Unsupported(_) | ConversionError::User(_) => {
                AddressValidationError::UnsupportedReceiver
            }
        })?;
    Ok(match receiver {
        ZcashReceiverClass::Transparent => ReceiverKind::Transparent,
        ZcashReceiverClass::Ironwood => ReceiverKind::Ironwood,
    })
}

fn canonical_zcash(candidate: &str) -> Result<String, AddressValidationError> {
    ZcashAddress::try_from_encoded(candidate)
        .map(|address| address.encode())
        .map_err(|_| AddressValidationError::Malformed)
}

fn validate_candidate_shape(candidate: &str) -> Result<(), AddressValidationError> {
    if !(8..=MAX_ADDRESS_BYTES).contains(&candidate.len())
        || !candidate.is_ascii()
        || candidate.chars().any(char::is_whitespace)
    {
        return Err(AddressValidationError::Malformed);
    }
    Ok(())
}

fn hash_program(path: &Path, expected_len: u64) -> Result<[u8; 32], ValidatorConfigError> {
    let mut file = File::open(path).map_err(|_| ValidatorConfigError::ProgramUnavailable)?;
    let mut hasher = Sha256::new();
    let copied = io::copy(
        &mut Read::by_ref(&mut file).take(MAX_PROGRAM_BYTES + 1),
        &mut hasher,
    )
    .map_err(|_| ValidatorConfigError::ProgramUnavailable)?;
    if copied != expected_len || copied > MAX_PROGRAM_BYTES {
        return Err(ValidatorConfigError::UnsafeProgram);
    }
    Ok(hasher.finalize().into())
}

fn write_candidate(child: &mut Child, candidate: &str) -> Result<(), CommandValidationError> {
    let mut stdin = child
        .stdin
        .take()
        .ok_or(CommandValidationError::Unavailable)?;
    stdin
        .write_all(candidate.as_bytes())
        .and_then(|_| stdin.write_all(b"\n"))
        .map_err(|_| CommandValidationError::Unavailable)
}

struct BoundedOutput {
    bytes: Vec<u8>,
    exceeded: bool,
}

fn spawn_bounded_reader<R: Read + Send + 'static>(
    mut reader: R,
) -> thread::JoinHandle<io::Result<BoundedOutput>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        reader
            .by_ref()
            .take(MAX_OUTPUT_BYTES + 1)
            .read_to_end(&mut bytes)?;
        let exceeded = u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_OUTPUT_BYTES;
        Ok(BoundedOutput { bytes, exceeded })
    })
}

fn join_reader(
    reader: thread::JoinHandle<io::Result<BoundedOutput>>,
) -> Result<BoundedOutput, CommandValidationError> {
    reader
        .join()
        .map_err(|_| CommandValidationError::Unavailable)?
        .map_err(|_| CommandValidationError::Unavailable)
}

fn wait_bounded(
    child: &mut Child,
    timeout: Duration,
) -> Result<ExitStatus, CommandValidationError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(CommandValidationError::Unavailable)?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CommandValidationError::Unavailable);
            }
            Err(_) => return Err(CommandValidationError::Unavailable),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandValidationError {
    Rejected,
    Unavailable,
}

/// Invalid or unsafe Wolf command configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ValidatorConfigError {
    /// The command path is not absolute and canonical.
    #[error("Wcash validator path must be absolute and canonical")]
    ProgramPath,
    /// The configured digest cannot identify a binary.
    #[error("Wcash validator digest must be nonzero")]
    ZeroDigest,
    /// The validation deadline is zero or excessive.
    #[error("Wcash validator timeout must be greater than zero and at most ten seconds")]
    Timeout,
    /// The command could not be inspected.
    #[error("Wcash validator program is unavailable")]
    ProgramUnavailable,
    /// The command or its permissions are unsafe.
    #[error("Wcash validator program ownership or permissions are unsafe")]
    UnsafeProgram,
    /// The command directory is not protected from replacement.
    #[error("Wcash validator program directory is not owner-controlled")]
    UnsafeProgramDirectory,
    /// The command bytes do not match the deployment pin.
    #[error("Wcash validator program digest does not match")]
    DigestMismatch,
    /// The pool address validator is supported only on Unix deployment hosts.
    #[error("Wcash validator is supported only on Unix")]
    UnsupportedPlatform,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use zcash_address::{unified::Encoding, ToAddress};

    fn testnet_transparent() -> String {
        ZcashAddress::from_transparent_p2pkh(NetworkType::Test, [7; 20]).encode()
    }

    fn mainnet_transparent() -> String {
        ZcashAddress::from_transparent_p2pkh(NetworkType::Main, [7; 20]).encode()
    }

    fn testnet_ironwood() -> String {
        let unified = unified::Address::try_from_items(vec![unified::Receiver::Orchard([9; 43])])
            .expect("fixture unified address is valid");
        ZcashAddress::from_unified(NetworkType::Test, unified).encode()
    }

    #[test]
    fn zcash_parser_accepts_only_testnet_transparent_or_ironwood() {
        assert_eq!(
            parse_supported_zcash(&testnet_transparent(), NetworkType::Test),
            Ok(ReceiverKind::Transparent)
        );
        assert_eq!(
            parse_supported_zcash(&testnet_ironwood(), NetworkType::Test),
            Ok(ReceiverKind::Ironwood)
        );
        assert_eq!(
            parse_supported_zcash(&mainnet_transparent(), NetworkType::Test),
            Err(AddressValidationError::WrongNetwork)
        );
        let sapling = ZcashAddress::from_sapling(NetworkType::Test, [11; 43]).encode();
        assert_eq!(
            parse_supported_zcash(&sapling, NetworkType::Test),
            Err(AddressValidationError::UnsupportedReceiver)
        );
        let tex = ZcashAddress::from_tex(NetworkType::Test, [12; 20]).encode();
        assert_eq!(
            parse_supported_zcash(&tex, NetworkType::Test),
            Err(AddressValidationError::UnsupportedReceiver)
        );
    }

    #[cfg(unix)]
    fn command_fixture() -> (tempfile::TempDir, WcashCommandValidator) {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = tempfile::tempdir().expect("temporary directory is created");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("fixture directory permissions are set");
        let program = directory.path().join("wcash-wallet-fixture");
        fs::write(
            &program,
            concat!(
                "#!/bin/sh\n",
                "IFS= read -r candidate\n",
                "if [ \"$1 $2 $3\" = \"--network testnet validate-address\" ] && ",
                "[ \"$candidate\" = \"WTtestfixture\" ]; then\n",
                "printf '%s\\n' '{\"network\":\"testnet\",\"receiver_kind\":\"transparent_p2pkh\",\"canonical\":\"WTtestfixture\"}'\n",
                "exit 0\n",
                "fi\n",
                "if [ \"$1 $2 $3\" = \"--network regtest validate-address\" ] && ",
                "[ \"$candidate\" = \"WRtestfixture\" ]; then\n",
                "printf '%s\\n' '{\"network\":\"regtest\",\"receiver_kind\":\"ironwood\",\"canonical\":\"WRtestfixture\"}'\n",
                "exit 0\n",
                "fi\n",
                "exit 2\n",
            ),
        )
        .expect("fixture command is written");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o500))
            .expect("fixture command is executable");
        let metadata = fs::metadata(&program).expect("fixture metadata exists");
        let canonical = fs::canonicalize(&program).expect("fixture path is canonical");
        let digest = hash_program(&canonical, metadata.len()).expect("fixture digest is computed");
        let validator =
            WcashCommandValidator::new(canonical, digest, metadata.uid(), Duration::from_secs(1))
                .expect("fixture validator is accepted");
        (directory, validator)
    }

    #[cfg(unix)]
    #[test]
    fn composite_validator_keeps_assets_and_networks_separate() {
        let (_directory, command) = command_fixture();
        let validator = TestnetAddressValidator::new(command);
        let wcash = validator
            .validate(Asset::Wec, ChainNetwork::Testnet, "WTtestfixture")
            .expect("Wcash fixture is valid");
        assert_eq!(wcash.asset(), Asset::Wec);
        assert_eq!(wcash.receiver_kind(), ReceiverKind::Transparent);
        assert_eq!(
            validator.validate(Asset::Wec, ChainNetwork::Testnet, &testnet_transparent()),
            Err(AddressValidationError::WrongAsset)
        );
        assert_eq!(
            validator.validate(Asset::Wec, ChainNetwork::Testnet, "WRtestfixture"),
            Err(AddressValidationError::WrongNetwork)
        );
        assert_eq!(
            validator.validate(Asset::Zec, ChainNetwork::Testnet, "WTtestfixture"),
            Err(AddressValidationError::WrongAsset)
        );
        assert!(validator
            .validate(Asset::Zec, ChainNetwork::Testnet, &testnet_ironwood())
            .is_ok());
        assert_eq!(
            validator.validate(Asset::Zec, ChainNetwork::Mainnet, &mainnet_transparent()),
            Err(AddressValidationError::AuthorityUnavailable)
        );
    }

    #[cfg(unix)]
    #[test]
    fn command_integrity_and_output_shape_fail_closed() {
        use std::os::unix::fs::MetadataExt;

        let (directory, validator) = command_fixture();
        assert!(validator.verify_program().is_ok());
        let metadata = fs::metadata(&validator.program).expect("fixture metadata exists");
        assert!(matches!(
            WcashCommandValidator::new(
                validator.program.clone(),
                [1; 32],
                metadata.uid(),
                Duration::from_secs(1),
            ),
            Err(ValidatorConfigError::DigestMismatch)
        ));
        drop(directory);
        assert!(matches!(
            validator.validate_for(WcashNetwork::Testnet, "WTtestfixture"),
            Err(CommandValidationError::Unavailable)
        ));
    }
}
