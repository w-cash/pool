//! Atomic local journal for one-way PCZT stage transitions.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Take, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{PipelineStage, ZecPayoutError};

const SCHEMA_VERSION: u16 = 1;
const JOURNAL_CHECKSUM_DOMAIN: &[u8] = b"zecwec/zec-pczt-journal/v1";
const MAX_JOURNAL_BYTES: u64 = 12 * 1024 * 1024;
const MAX_PCZT_BYTES: usize = 8 * 1024 * 1024;
const MAX_RAW_TX_HEX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct JournalRecord {
    pub(crate) batch_id: Uuid,
    pub(crate) pipeline_commitment: [u8; 32],
    pub(crate) portal_commitment: [u8; 32],
    pub(crate) output_total_zat: u64,
    pub(crate) stage: StoredStage,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "stage", rename_all = "snake_case")]
pub(crate) enum StoredStage {
    Reserved,
    Created {
        pczt: String,
        privacy_policy: String,
    },
    CreatedVerified {
        pczt: String,
        privacy_policy: String,
    },
    Proved {
        pczt: String,
        privacy_policy: String,
    },
    ProvedVerified {
        pczt: String,
        privacy_policy: String,
    },
    Signed {
        pczt: String,
        privacy_policy: String,
    },
    SignedVerified {
        pczt: String,
        privacy_policy: String,
        network_fee_zat: u64,
    },
    Extracted {
        raw_transaction: String,
        transaction_id: String,
        network_fee_zat: u64,
    },
    BroadcastUnresolved {
        raw_transaction: String,
        transaction_id: String,
        network_fee_zat: u64,
    },
    Rejected {
        transaction_id: String,
    },
    Completed {
        raw_transaction: String,
        transaction_id: String,
        network_fee_zat: u64,
    },
}

impl StoredStage {
    pub(crate) const fn public_stage(&self) -> PipelineStage {
        match self {
            Self::Reserved => PipelineStage::Reserved,
            Self::Created { .. } => PipelineStage::Created,
            Self::CreatedVerified { .. } => PipelineStage::CreatedVerified,
            Self::Proved { .. } => PipelineStage::Proved,
            Self::ProvedVerified { .. } => PipelineStage::ProvedVerified,
            Self::Signed { .. } => PipelineStage::Signed,
            Self::SignedVerified { .. } => PipelineStage::SignedVerified,
            Self::Extracted { .. } => PipelineStage::Extracted,
            Self::BroadcastUnresolved { .. } => PipelineStage::BroadcastUnresolved,
            Self::Rejected { .. } => PipelineStage::Rejected,
            Self::Completed { .. } => PipelineStage::Completed,
        }
    }

    fn validate(&self) -> Result<(), ZecPayoutError> {
        match self {
            Self::Reserved => Ok(()),
            Self::Created {
                pczt,
                privacy_policy,
            }
            | Self::CreatedVerified {
                pczt,
                privacy_policy,
            }
            | Self::Proved {
                pczt,
                privacy_policy,
            }
            | Self::ProvedVerified {
                pczt,
                privacy_policy,
            }
            | Self::Signed {
                pczt,
                privacy_policy,
            }
            | Self::SignedVerified {
                pczt,
                privacy_policy,
                network_fee_zat: _,
            } => {
                if pczt.is_empty()
                    || pczt.len() > MAX_PCZT_BYTES
                    || !pczt.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
                    })
                    || !matches!(
                        privacy_policy.as_str(),
                        "FullPrivacy" | "AllowRevealedAmounts" | "AllowRevealedRecipients"
                    )
                {
                    return Err(ZecPayoutError::JournalCorrupt);
                }
                Ok(())
            }
            Self::Extracted {
                raw_transaction,
                transaction_id,
                network_fee_zat,
            }
            | Self::BroadcastUnresolved {
                raw_transaction,
                transaction_id,
                network_fee_zat,
            }
            | Self::Completed {
                raw_transaction,
                transaction_id,
                network_fee_zat,
            } => {
                if *network_fee_zat == 0 {
                    return Err(ZecPayoutError::JournalCorrupt);
                }
                validate_raw_transaction(raw_transaction)?;
                validate_transaction_id(transaction_id)
            }
            Self::Rejected { transaction_id } => validate_transaction_id(transaction_id),
        }
    }
}

fn validate_raw_transaction(raw_transaction: &str) -> Result<(), ZecPayoutError> {
    if raw_transaction.is_empty()
        || raw_transaction.len() > MAX_RAW_TX_HEX_BYTES
        || !raw_transaction.len().is_multiple_of(2)
        || !raw_transaction
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ZecPayoutError::JournalCorrupt);
    }
    Ok(())
}

fn validate_transaction_id(transaction_id: &str) -> Result<(), ZecPayoutError> {
    if transaction_id.len() != 64
        || !transaction_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ZecPayoutError::JournalCorrupt);
    }
    Ok(())
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
    pub(crate) fn open(directory: &Path) -> Result<Self, ZecPayoutError> {
        std::fs::create_dir_all(directory).map_err(|_| ZecPayoutError::JournalUnavailable)?;
        let metadata =
            std::fs::symlink_metadata(directory).map_err(|_| ZecPayoutError::JournalUnavailable)?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(ZecPayoutError::JournalUnavailable);
        }
        #[cfg(unix)]
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| ZecPayoutError::JournalUnavailable)?;

        let journal = Self {
            directory: directory.to_path_buf(),
        };
        let lock = journal.open_lock()?;
        lock.sync_all()
            .map_err(|_| ZecPayoutError::JournalUnavailable)?;
        Ok(journal)
    }

    pub(crate) fn with_exclusive_lock<T>(
        &self,
        operation: impl FnOnce() -> Result<T, ZecPayoutError>,
    ) -> Result<T, ZecPayoutError> {
        let lock = self.open_lock()?;
        lock.lock()
            .map_err(|_| ZecPayoutError::JournalUnavailable)?;
        operation()
    }

    pub(crate) fn load(&self, batch_id: Uuid) -> Result<Option<JournalRecord>, ZecPayoutError> {
        let path = self.record_path(batch_id);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ZecPayoutError::JournalUnavailable),
        };
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(ZecPayoutError::JournalCorrupt);
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ZecPayoutError::JournalCorrupt);
        }

        let file = File::open(path).map_err(|_| ZecPayoutError::JournalUnavailable)?;
        let mut bytes = Vec::new();
        let mut bounded: Take<File> = file.take(MAX_JOURNAL_BYTES + 1);
        bounded
            .read_to_end(&mut bytes)
            .map_err(|_| ZecPayoutError::JournalUnavailable)?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(ZecPayoutError::JournalCorrupt);
        }
        let envelope: Envelope =
            serde_json::from_slice(&bytes).map_err(|_| ZecPayoutError::JournalCorrupt)?;
        if envelope.schema_version != SCHEMA_VERSION
            || envelope.record.batch_id != batch_id
            || envelope.checksum != record_checksum(&envelope.record)?
            || envelope
                .record
                .pipeline_commitment
                .iter()
                .all(|byte| *byte == 0)
            || envelope
                .record
                .portal_commitment
                .iter()
                .all(|byte| *byte == 0)
            || envelope.record.output_total_zat == 0
        {
            return Err(ZecPayoutError::JournalCorrupt);
        }
        envelope.record.stage.validate()?;
        Ok(Some(envelope.record))
    }

    pub(crate) fn store(&self, record: &JournalRecord) -> Result<(), ZecPayoutError> {
        record.stage.validate()?;
        let envelope = Envelope {
            schema_version: SCHEMA_VERSION,
            record: record.clone(),
            checksum: record_checksum(record)?,
        };
        let bytes =
            serde_json::to_vec(&envelope).map_err(|_| ZecPayoutError::JournalUnavailable)?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(ZecPayoutError::JournalUnavailable);
        }

        let temporary = self.directory.join(format!(
            ".{}.{}.tmp",
            record.batch_id.simple(),
            Uuid::new_v4().simple()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&temporary)
            .map_err(|_| ZecPayoutError::JournalUnavailable)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| ZecPayoutError::JournalUnavailable)?;
        std::fs::rename(&temporary, self.record_path(record.batch_id))
            .map_err(|_| ZecPayoutError::JournalUnavailable)?;
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ZecPayoutError::JournalUnavailable)
    }

    fn open_lock(&self) -> Result<File, ZecPayoutError> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        options.mode(0o600);
        options
            .open(self.directory.join(".signer.lock"))
            .map_err(|_| ZecPayoutError::JournalUnavailable)
    }

    fn record_path(&self, batch_id: Uuid) -> PathBuf {
        self.directory.join(format!("{}.json", batch_id.simple()))
    }
}

fn record_checksum(record: &JournalRecord) -> Result<String, ZecPayoutError> {
    let serialized = serde_json::to_vec(record).map_err(|_| ZecPayoutError::JournalUnavailable)?;
    let mut hasher = Sha256::new();
    hasher.update(JOURNAL_CHECKSUM_DOMAIN);
    hasher.update(serialized);
    Ok(hex::encode(hasher.finalize()))
}
