//! Atomic, owner-private journal for one-way WEC payout transitions.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Take, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{BroadcastDisposition, WecPayoutError, WecPipelineStage};

const SCHEMA_VERSION: u16 = 1;
const CHECKSUM_DOMAIN: &[u8] = b"zecwec/wec-payout-journal/v1";
const MAX_JOURNAL_BYTES: u64 = 6 * 1024 * 1024;
const MAX_RAW_TRANSACTION_HEX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct JournalRecord {
    pub(crate) batch_id: Uuid,
    pub(crate) pipeline_commitment: [u8; 32],
    pub(crate) portal_commitment: [u8; 32],
    pub(crate) output_total_zat: u64,
    pub(crate) stage: StoredStage,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct StoredArtifact {
    pub(crate) raw_transaction_hex: String,
    pub(crate) transaction_id: String,
    pub(crate) unsigned_digest: [u8; 32],
    pub(crate) fee_zat: u64,
    pub(crate) target_height: u32,
    pub(crate) expiry_height: u32,
}

impl StoredArtifact {
    fn validate(&self) -> Result<(), WecPayoutError> {
        if self.raw_transaction_hex.is_empty()
            || self.raw_transaction_hex.len() > MAX_RAW_TRANSACTION_HEX_BYTES
            || !self.raw_transaction_hex.len().is_multiple_of(2)
            || !self
                .raw_transaction_hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || self.transaction_id.len() != 64
            || !self
                .transaction_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || self.unsigned_digest == [0; 32]
            || self.fee_zat == 0
            || self.target_height == 0
            || self.expiry_height <= self.target_height
        {
            return Err(WecPayoutError::JournalCorrupt);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "stage", rename_all = "snake_case")]
pub(crate) enum StoredStage {
    Reserved,
    Signed {
        artifact: StoredArtifact,
    },
    BroadcastUnresolved {
        artifact: StoredArtifact,
    },
    Rejected {
        artifact: StoredArtifact,
    },
    Completed {
        artifact: StoredArtifact,
        disposition: StoredBroadcastDisposition,
    },
}

impl StoredStage {
    pub(crate) const fn public_stage(&self) -> WecPipelineStage {
        match self {
            Self::Reserved => WecPipelineStage::Reserved,
            Self::Signed { .. } => WecPipelineStage::Signed,
            Self::BroadcastUnresolved { .. } => WecPipelineStage::BroadcastUnresolved,
            Self::Rejected { .. } => WecPipelineStage::Rejected,
            Self::Completed { .. } => WecPipelineStage::Completed,
        }
    }

    pub(crate) fn artifact(&self) -> Option<&StoredArtifact> {
        match self {
            Self::Reserved => None,
            Self::Signed { artifact }
            | Self::BroadcastUnresolved { artifact }
            | Self::Rejected { artifact }
            | Self::Completed { artifact, .. } => Some(artifact),
        }
    }

    fn validate(&self) -> Result<(), WecPayoutError> {
        if let Some(artifact) = self.artifact() {
            artifact.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StoredBroadcastDisposition {
    Accepted,
    AlreadyKnown,
}

impl From<BroadcastDisposition> for StoredBroadcastDisposition {
    fn from(value: BroadcastDisposition) -> Self {
        match value {
            BroadcastDisposition::Accepted => Self::Accepted,
            BroadcastDisposition::AlreadyKnown => Self::AlreadyKnown,
        }
    }
}

impl From<StoredBroadcastDisposition> for BroadcastDisposition {
    fn from(value: StoredBroadcastDisposition) -> Self {
        match value {
            StoredBroadcastDisposition::Accepted => Self::Accepted,
            StoredBroadcastDisposition::AlreadyKnown => Self::AlreadyKnown,
        }
    }
}

#[derive(Deserialize, Serialize)]
struct Envelope {
    schema_version: u16,
    record: JournalRecord,
    checksum: String,
}

pub(crate) struct Journal {
    directory: PathBuf,
}

impl Journal {
    #[cfg(unix)]
    pub(crate) fn open(directory: &Path) -> Result<Self, WecPayoutError> {
        std::fs::create_dir_all(directory).map_err(|_| WecPayoutError::JournalUnavailable)?;
        let canonical =
            std::fs::canonicalize(directory).map_err(|_| WecPayoutError::JournalUnavailable)?;
        if canonical != directory {
            return Err(WecPayoutError::JournalUnavailable);
        }
        let metadata =
            std::fs::symlink_metadata(directory).map_err(|_| WecPayoutError::JournalUnavailable)?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(WecPayoutError::JournalUnavailable);
        }
        #[cfg(unix)]
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| WecPayoutError::JournalUnavailable)?;

        let journal = Self {
            directory: directory.to_path_buf(),
        };
        let lock = journal.open_lock()?;
        lock.sync_all()
            .map_err(|_| WecPayoutError::JournalUnavailable)?;
        File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| WecPayoutError::JournalUnavailable)?;
        Ok(journal)
    }

    #[cfg(not(unix))]
    pub(crate) fn open(_directory: &Path) -> Result<Self, WecPayoutError> {
        // The payout journal's owner-only mode guarantee is part of the
        // security boundary. Do not silently weaken it on another platform.
        Err(WecPayoutError::JournalUnavailable)
    }

    pub(crate) fn with_exclusive_lock<T>(
        &self,
        operation: impl FnOnce() -> Result<T, WecPayoutError>,
    ) -> Result<T, WecPayoutError> {
        let lock = self.open_lock()?;
        lock.lock()
            .map_err(|_| WecPayoutError::JournalUnavailable)?;
        operation()
    }

    pub(crate) fn load(&self, batch_id: Uuid) -> Result<Option<JournalRecord>, WecPayoutError> {
        let path = self.record_path(batch_id);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(WecPayoutError::JournalUnavailable),
        };
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(WecPayoutError::JournalCorrupt);
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o777 != 0o600 || metadata.nlink() != 1 {
            return Err(WecPayoutError::JournalCorrupt);
        }

        let file = File::open(path).map_err(|_| WecPayoutError::JournalUnavailable)?;
        let mut bytes = Vec::new();
        let mut bounded: Take<File> = file.take(MAX_JOURNAL_BYTES + 1);
        bounded
            .read_to_end(&mut bytes)
            .map_err(|_| WecPayoutError::JournalUnavailable)?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(WecPayoutError::JournalCorrupt);
        }
        let envelope: Envelope =
            serde_json::from_slice(&bytes).map_err(|_| WecPayoutError::JournalCorrupt)?;
        if envelope.schema_version != SCHEMA_VERSION
            || envelope.record.batch_id != batch_id
            || envelope.checksum != checksum(&envelope.record)?
            || envelope.record.pipeline_commitment == [0; 32]
            || envelope.record.portal_commitment == [0; 32]
            || envelope.record.output_total_zat == 0
        {
            return Err(WecPayoutError::JournalCorrupt);
        }
        envelope.record.stage.validate()?;
        Ok(Some(envelope.record))
    }

    pub(crate) fn store(&self, record: &JournalRecord) -> Result<(), WecPayoutError> {
        record.stage.validate()?;
        let envelope = Envelope {
            schema_version: SCHEMA_VERSION,
            record: record.clone(),
            checksum: checksum(record)?,
        };
        let bytes =
            serde_json::to_vec(&envelope).map_err(|_| WecPayoutError::JournalUnavailable)?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(WecPayoutError::JournalUnavailable);
        }

        let temporary = self.directory.join(format!(
            ".{}.{}.tmp",
            record.batch_id.simple(),
            Uuid::new_v4().simple()
        ));
        let result = self.write_and_replace(record.batch_id, &temporary, &bytes);
        if result.is_err() {
            let _cleanup = std::fs::remove_file(&temporary);
        }
        result
    }

    fn write_and_replace(
        &self,
        batch_id: Uuid,
        temporary: &Path,
        bytes: &[u8],
    ) -> Result<(), WecPayoutError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(temporary)
            .map_err(|_| WecPayoutError::JournalUnavailable)?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| WecPayoutError::JournalUnavailable)?;
        std::fs::rename(temporary, self.record_path(batch_id))
            .map_err(|_| WecPayoutError::JournalUnavailable)?;
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| WecPayoutError::JournalUnavailable)
    }

    fn open_lock(&self) -> Result<File, WecPayoutError> {
        let path = self.directory.join(".signer.lock");
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(WecPayoutError::JournalUnavailable);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(WecPayoutError::JournalUnavailable),
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options
            .open(&path)
            .map_err(|_| WecPayoutError::JournalUnavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| WecPayoutError::JournalUnavailable)?;
        #[cfg(unix)]
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(WecPayoutError::JournalUnavailable);
        }
        Ok(file)
    }

    fn record_path(&self, batch_id: Uuid) -> PathBuf {
        self.directory.join(format!("{}.json", batch_id.simple()))
    }
}

fn checksum(record: &JournalRecord) -> Result<String, WecPayoutError> {
    let serialized = serde_json::to_vec(record).map_err(|_| WecPayoutError::JournalUnavailable)?;
    let mut hasher = Sha256::new();
    hasher.update(CHECKSUM_DOMAIN);
    hasher.update(serialized);
    Ok(hex::encode(hasher.finalize()))
}
