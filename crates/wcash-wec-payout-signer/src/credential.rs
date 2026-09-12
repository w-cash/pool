//! Bounded spending-seed input with no argument or environment representation.

use std::{
    fmt,
    fs::File,
    io::{self, IsTerminal, Read},
    path::{Component, Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use zeroize::Zeroizing;

use crate::WecPayoutError;

const MIN_SEED_BYTES: usize = 32;
const MAX_SEED_BYTES: usize = 252;
const MAX_ENCODED_SEED_BYTES: u64 = (MAX_SEED_BYTES as u64) * 2 + 2;

/// Only supported sources of Wcash spending authority.
///
/// The value is never accepted through command-line arguments or environment
/// variables. File mode and ownership are checked again on every read.
pub enum SeedSource {
    /// Exact hex seed from a private, single-link regular file.
    ProtectedFile {
        /// Absolute canonical path, redacted from `Debug`.
        path: PathBuf,
        /// Required Unix owner identity.
        trusted_uid: u32,
    },
    /// Exact hex seed from non-terminal standard input.
    Stdin,
}

impl SeedSource {
    /// Creates a protected-file source. The path must be absolute and the file
    /// must be owned by `trusted_uid` with mode exactly `0600` on Unix.
    pub fn protected_file(path: impl Into<PathBuf>, trusted_uid: u32) -> Self {
        Self::ProtectedFile {
            path: path.into(),
            trusted_uid,
        }
    }

    /// Selects non-terminal standard input as the one-shot seed source.
    pub const fn stdin() -> Self {
        Self::Stdin
    }

    pub(crate) fn read(&self) -> Result<SecretSeed, WecPayoutError> {
        match self {
            Self::ProtectedFile { path, trusted_uid } => read_protected_file(path, *trusted_uid),
            Self::Stdin => {
                let stdin = io::stdin();
                if stdin.is_terminal() {
                    return Err(WecPayoutError::UnsafeCredential);
                }
                read_encoded_seed(stdin.lock())
            }
        }
    }
}

impl fmt::Debug for SeedSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtectedFile { .. } => formatter.write_str("ProtectedFile([REDACTED])"),
            Self::Stdin => formatter.write_str("Stdin([REDACTED])"),
        }
    }
}

/// Zeroizing Wcash master seed supplied only to the native wallet transport.
pub struct SecretSeed(Zeroizing<Vec<u8>>);

impl SecretSeed {
    /// Borrows the secret for a native wallet call.
    ///
    /// Implementations must write it only to the isolated wallet's standard
    /// input or equivalent private in-process boundary and must never log it.
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretSeed([REDACTED])")
    }
}

#[cfg(unix)]
fn read_protected_file(path: &Path, trusted_uid: u32) -> Result<SecretSeed, WecPayoutError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(WecPayoutError::UnsafeCredential);
    }
    let path_metadata =
        std::fs::symlink_metadata(path).map_err(|_| WecPayoutError::UnsafeCredential)?;
    validate_file_metadata(&path_metadata, trusted_uid)?;
    let canonical = std::fs::canonicalize(path).map_err(|_| WecPayoutError::UnsafeCredential)?;
    if canonical != path {
        return Err(WecPayoutError::UnsafeCredential);
    }
    let parent = path.parent().ok_or(WecPayoutError::UnsafeCredential)?;
    let parent_metadata =
        std::fs::symlink_metadata(parent).map_err(|_| WecPayoutError::UnsafeCredential)?;
    let parent_uid = parent_metadata.uid();
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.file_type().is_symlink()
        || (parent_uid != 0 && parent_uid != trusted_uid)
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(WecPayoutError::UnsafeCredential);
    }

    let file = File::open(path).map_err(|_| WecPayoutError::UnsafeCredential)?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| WecPayoutError::UnsafeCredential)?;
    validate_file_metadata(&opened_metadata, trusted_uid)?;
    if opened_metadata.dev() != path_metadata.dev() || opened_metadata.ino() != path_metadata.ino()
    {
        return Err(WecPayoutError::UnsafeCredential);
    }
    read_encoded_seed(file)
}

#[cfg(unix)]
fn validate_file_metadata(
    metadata: &std::fs::Metadata,
    trusted_uid: u32,
) -> Result<(), WecPayoutError> {
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != trusted_uid
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() == 0
        || metadata.len() > MAX_ENCODED_SEED_BYTES
    {
        return Err(WecPayoutError::UnsafeCredential);
    }
    Ok(())
}

#[cfg(not(unix))]
fn read_protected_file(_path: &Path, _trusted_uid: u32) -> Result<SecretSeed, WecPayoutError> {
    Err(WecPayoutError::UnsafeCredential)
}

fn read_encoded_seed(reader: impl Read) -> Result<SecretSeed, WecPayoutError> {
    let mut encoded = Zeroizing::new(String::new());
    reader
        .take(MAX_ENCODED_SEED_BYTES + 1)
        .read_to_string(&mut encoded)
        .map_err(|_| WecPayoutError::UnsafeCredential)?;
    if u64::try_from(encoded.len()).unwrap_or(u64::MAX) > MAX_ENCODED_SEED_BYTES {
        return Err(WecPayoutError::UnsafeCredential);
    }
    let trimmed = encoded.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
        return Err(WecPayoutError::UnsafeCredential);
    }
    let decoded =
        Zeroizing::new(hex::decode(trimmed).map_err(|_| WecPayoutError::UnsafeCredential)?);
    if !(MIN_SEED_BYTES..=MAX_SEED_BYTES).contains(&decoded.len()) {
        return Err(WecPayoutError::UnsafeCredential);
    }
    Ok(SecretSeed(decoded))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_always_redacted() {
        let secret = read_encoded_seed(format!("{}\n", "42".repeat(32)).as_bytes())
            .unwrap_or_else(|error| panic!("unexpected seed failure: {error}"));
        assert_eq!(format!("{secret:?}"), "SecretSeed([REDACTED])");
    }

    #[test]
    fn seed_shape_is_bounded() {
        assert_eq!(
            read_encoded_seed("42".repeat(31).as_bytes()).err(),
            Some(WecPayoutError::UnsafeCredential)
        );
        assert_eq!(
            read_encoded_seed("zz".repeat(32).as_bytes()).err(),
            Some(WecPayoutError::UnsafeCredential)
        );
        assert_eq!(
            read_encoded_seed(format!("{} {}", "42".repeat(32), "43").as_bytes()).err(),
            Some(WecPayoutError::UnsafeCredential)
        );
    }
}
