use std::fmt;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    error::invalid, CanonicalUuid, FixedHex, Hex108, Hex1344, Hex32, Hex4, ProtocolError, TargetLe,
};

/// Version implemented by every backend message in this crate.
pub const BACKEND_PROTOCOL_VERSION: u16 = 1;

/// Maximum JSON payload accepted in one backend frame.
pub const MAX_BACKEND_PAYLOAD_BYTES: usize = 64 * 1024;

/// Compatibility name for the backend frame payload limit.
pub const MAX_FRAME_BYTES: usize = MAX_BACKEND_PAYLOAD_BYTES;

/// Number of bytes in the backend's big-endian frame-length prefix.
pub const BACKEND_LENGTH_PREFIX_BYTES: usize = 4;

/// Maximum number of journal events returned in one bounded page.
pub const MAX_EVENT_PAGE_ITEMS: u16 = 1_024;

/// Maximum monetary value representable by either 21-million-coin chain.
///
/// Wcash and Zcash both use eight decimal places, so this bound is expressed
/// in their shared smallest unit (zatoshi).
pub const MAX_CHAIN_VALUE_ZAT: u64 = 2_100_000_000_000_000;

/// Defensive wire bound for a chain's coinbase maturity requirement.
pub const MAX_MATURITY_CONFIRMATIONS: u32 = 1_000_000;

/// Canonical CompactSize prefix for a 1,344-byte Equihash `(200, 9)` solution.
pub const EQUIHASH_SOLUTION_COMPACT_SIZE: [u8; 3] = [0xfd, 0x40, 0x05];

/// Domain separator for the stable proof identity returned in a share receipt.
pub const SHARE_ID_DOMAIN: &[u8] = b"wcash-pool/share-id/v1";

/// Domain separator for immutable worker-and-target attribution.
pub const ATTRIBUTION_ID_DOMAIN: &[u8] = b"wcash-pool/attribution-id/v1";

fn encode_length_frame<T: Serialize>(message: &T) -> Result<Vec<u8>, ProtocolError> {
    let payload =
        serde_json::to_vec(message).map_err(|error| ProtocolError::Json(error.to_string()))?;
    if payload.is_empty() {
        return Err(ProtocolError::EmptyFrame {
            protocol: "backend",
        });
    }
    if payload.len() > MAX_BACKEND_PAYLOAD_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            protocol: "backend",
            maximum: MAX_BACKEND_PAYLOAD_BYTES,
            actual: payload.len(),
        });
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| invalid("backend frame length", "does not fit in u32"))?;
    let mut frame = Vec::with_capacity(BACKEND_LENGTH_PREFIX_BYTES + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn decode_length_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, ProtocolError> {
    let prefix = frame
        .get(..BACKEND_LENGTH_PREFIX_BYTES)
        .ok_or(ProtocolError::MissingLengthPrefix)?;
    let declared = u32::from_be_bytes(
        prefix
            .try_into()
            .map_err(|_| ProtocolError::MissingLengthPrefix)?,
    ) as usize;
    if declared == 0 {
        return Err(ProtocolError::EmptyFrame {
            protocol: "backend",
        });
    }
    if declared > MAX_BACKEND_PAYLOAD_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            protocol: "backend",
            maximum: MAX_BACKEND_PAYLOAD_BYTES,
            actual: declared,
        });
    }
    let payload = &frame[BACKEND_LENGTH_PREFIX_BYTES..];
    if payload.len() != declared {
        return Err(ProtocolError::InvalidFrameLength {
            declared,
            actual: payload.len(),
        });
    }
    serde_json::from_slice(payload).map_err(|error| ProtocolError::Json(error.to_string()))
}

/// Stable worker attribution resolved by the Internet-facing pool edge.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerIdentity {
    /// Pool account identifier. It is not accepted from a miner directly.
    pub account_id: CanonicalUuid,
    /// Worker identifier within the account.
    pub worker_id: CanonicalUuid,
    /// Bounded operator-facing worker label.
    pub label: String,
}

impl fmt::Debug for WorkerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerIdentity")
            .field("account_id", &"[REDACTED]")
            .field("worker_id", &"[REDACTED]")
            .field("label", &"[REDACTED]")
            .finish()
    }
}

impl WorkerIdentity {
    /// Checks the identity's bounded canonical label.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        require_non_nil_uuid(&self.account_id, "worker.account_id")?;
        require_non_nil_uuid(&self.worker_id, "worker.worker_id")?;
        validate_worker_label(&self.label)
    }
}

/// Exact proposal-validated work made available by the local backend.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobDescriptor {
    /// Backend-generated identifier for the exact frozen generation.
    pub job_id: Hex32,
    /// Proof-independent Wcash candidate hash in raw little-endian byte order.
    pub wcash_candidate_hash_le: Hex32,
    /// Version through compact difficulty, excluding nonce and solution.
    pub header_input: Hex108,
    /// Wcash predecessor hash in consensus/raw little-endian byte order.
    pub wcash_previous_hash_le: Hex32,
    /// Zcash predecessor hash in consensus/raw little-endian byte order.
    pub zcash_previous_hash_le: Hex32,
    /// Wcash candidate coinbase transaction ID in raw little-endian byte order.
    pub wcash_coinbase_txid_le: Hex32,
    /// Zcash parent coinbase transaction ID in raw little-endian byte order.
    pub zcash_coinbase_txid_le: Hex32,
    /// Authenticated Wcash target in little-endian numeric byte order.
    pub wcash_target_le: TargetLe,
    /// Authenticated Zcash target in little-endian numeric byte order.
    pub zcash_target_le: TargetLe,
    /// Candidate Wcash height.
    pub wcash_height: u32,
    /// Candidate Zcash height.
    pub zcash_height: u32,
    /// Exact value paid to the configured Wcash pool recipient, in zatoshi.
    pub wcash_reward_zat: u64,
    /// Exact value paid to the configured Zcash pool recipient, in zatoshi.
    pub zcash_reward_zat: u64,
    /// Confirmations required before this Wcash reward becomes mature.
    pub wcash_maturity_confirmations: u32,
    /// Confirmations required before this Zcash reward becomes mature.
    pub zcash_maturity_confirmations: u32,
    /// Backend-enforced maximum lifetime from activation.
    pub max_age_ms: u32,
}

impl JobDescriptor {
    /// Checks identifiers, targets, heights, and lifetime bounds.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero_hex(&self.job_id, "job.job_id")?;
        require_nonzero_hex(&self.wcash_candidate_hash_le, "job.wcash_candidate_hash_le")?;
        validate_v4_header_input(
            &self.header_input,
            "job.header_input.version",
            "job.header_input.time",
        )?;
        require_nonzero_hex(&self.wcash_previous_hash_le, "job.wcash_previous_hash_le")?;
        require_nonzero_hex(&self.zcash_previous_hash_le, "job.zcash_previous_hash_le")?;
        require_nonzero_hex(&self.wcash_coinbase_txid_le, "job.wcash_coinbase_txid_le")?;
        require_nonzero_hex(&self.zcash_coinbase_txid_le, "job.zcash_coinbase_txid_le")?;
        if self.header_input.as_bytes()[4..36] != self.zcash_previous_hash_le.as_bytes()[..] {
            return Err(invalid(
                "job.zcash_previous_hash_le",
                "must match the predecessor bytes in header_input",
            ));
        }
        require_nonzero_target(&self.wcash_target_le, "job.wcash_target_le")?;
        require_nonzero_target(&self.zcash_target_le, "job.zcash_target_le")?;
        if self.wcash_height == 0 {
            return Err(invalid("job.wcash_height", "must be positive"));
        }
        if self.zcash_height == 0 {
            return Err(invalid("job.zcash_height", "must be positive"));
        }
        validate_reward(self.wcash_reward_zat, "job.wcash_reward_zat")?;
        validate_reward(self.zcash_reward_zat, "job.zcash_reward_zat")?;
        validate_maturity(
            self.wcash_maturity_confirmations,
            "job.wcash_maturity_confirmations",
        )?;
        validate_maturity(
            self.zcash_maturity_confirmations,
            "job.zcash_maturity_confirmations",
        )?;
        if !(1..=600_000).contains(&self.max_age_ms) {
            return Err(invalid("job.max_age_ms", "must be in 1..=600000"));
        }
        Ok(())
    }
}

pub(crate) fn validate_v4_header_input(
    header_input: &Hex108,
    version_field: &'static str,
    time_field: &'static str,
) -> Result<(), ProtocolError> {
    if header_input.as_bytes()[..4] != [4, 0, 0, 0] {
        return Err(invalid(
            version_field,
            "must be the exact little-endian version bytes 04000000",
        ));
    }
    if header_input.as_bytes()[100..104]
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(invalid(time_field, "must be nonzero"));
    }
    Ok(())
}

/// Computes the raw little-endian Zcash parent-header hash for one submitted share.
///
/// Zcash serializes the fixed 108-byte pre-nonce header, the complete 32-byte
/// nonce, the canonical CompactSize encoding of a 1,344-byte solution, and the
/// raw solution bytes before applying SHA-256 twice. This helper deliberately
/// does not validate Equihash; it only binds a backend receipt to the exact
/// bytes submitted through this protocol.
pub fn canonical_parent_header_hash_le(
    header_input: &Hex108,
    nonce: &Hex32,
    solution: &Hex1344,
) -> Hex32 {
    let mut first = Sha256::new();
    first.update(header_input.as_bytes());
    first.update(nonce.as_bytes());
    first.update(EQUIHASH_SOLUTION_COMPACT_SIZE);
    first.update(solution.as_bytes());
    let first = first.finalize();
    Hex32::new(Sha256::digest(first).into())
}

/// Computes the stable identity of one exact submitted proof.
///
/// Worker identity and assigned target are intentionally excluded: the backend
/// stores them as the immutable attribution fingerprint for this proof, so a
/// retry with different attribution is a conflict rather than a second share.
pub fn canonical_share_id(job_id: &Hex32, time: &Hex4, nonce: &Hex32, solution: &Hex1344) -> Hex32 {
    let mut hasher = Sha256::new();
    hasher.update(SHARE_ID_DOMAIN);
    hasher.update(job_id.as_bytes());
    hasher.update(time.as_bytes());
    hasher.update(nonce.as_bytes());
    hasher.update(solution.as_bytes());
    Hex32::new(hasher.finalize().into())
}

/// Computes the stable attribution bound into every durable share receipt.
///
/// The canonical UUID bytes and explicit label length make this encoding
/// unambiguous. The assigned target is included so a retry cannot claim easier
/// work or another account after the matching journal event has been projected.
pub fn canonical_attribution_id(
    identity: &WorkerIdentity,
    target_le: &TargetLe,
) -> Result<Hex32, ProtocolError> {
    identity.validate()?;
    require_nonzero_target(target_le, "attribution.target_le")?;
    let label_len = u16::try_from(identity.label.len())
        .map_err(|_| invalid("worker.label", "length cannot be represented canonically"))?;
    let mut hasher = Sha256::new();
    hasher.update(ATTRIBUTION_ID_DOMAIN);
    hasher.update(identity.account_id.get().as_bytes());
    hasher.update(identity.worker_id.get().as_bytes());
    hasher.update(label_len.to_be_bytes());
    hasher.update(identity.label.as_bytes());
    hasher.update(target_le.as_bytes());
    Ok(Hex32::new(hasher.finalize().into()))
}

/// A job plus the backend-authenticated remaining time it may accept shares.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptableJob {
    /// Exact backend job.
    pub job: JobDescriptor,
    /// Remaining lifetime when the snapshot was created.
    pub accept_for_ms: u32,
}

impl AcceptableJob {
    fn validate(&self) -> Result<(), ProtocolError> {
        self.job.validate()?;
        if self.accept_for_ms == 0 || self.accept_for_ms > self.job.max_age_ms {
            return Err(invalid(
                "acceptable_job.accept_for_ms",
                "must be positive and no greater than the job's maximum age",
            ));
        }
        Ok(())
    }
}

/// Why the backend stopped accepting new work for a generation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobInvalidationReason {
    /// The Wcash predecessor changed.
    WcashTipChanged,
    /// The Zcash predecessor changed.
    ZcashTipChanged,
    /// Fresh same-tip work replaced the generation.
    Superseded,
    /// The backend's hard generation lifetime elapsed.
    Age,
}

/// Stable error codes returned across the local backend boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendErrorCode {
    /// Request sequencing or framing was invalid.
    InvalidRequest,
    /// The job is unknown or no longer acceptable.
    StaleJob,
    /// The submitted hash does not meet the issued share target.
    LowDifficulty,
    /// The Equihash solution is malformed or invalid.
    InvalidEquihash,
    /// The edge supplied a target outside the backend safety envelope.
    TargetOutOfRange,
    /// A durable share was replayed with different attribution.
    AttributionConflict,
    /// A bounded admission queue is currently full.
    Overloaded,
    /// A required node, journal, or backend invariant is unhealthy.
    BackendUnhealthy,
}

/// Explicit protocol-v1 features that must be negotiated before mining.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendCapability {
    /// Atomic snapshot followed by long-lived generation events.
    JobStreamV1,
    /// Share acknowledgements occur only after durable journal commit.
    DurableShareReceiptsV1,
    /// Journal events can be replayed from a stable cursor.
    EventReplayV1,
    /// Every share is independently classified against two network targets.
    DualTargetV1,
    /// Winning shares and reversible reward lifecycle changes are journaled.
    WinnerLifecycleV1,
}

/// Capabilities every protocol-v1 backend must advertise exactly once.
pub const REQUIRED_BACKEND_CAPABILITIES: [BackendCapability; 5] = [
    BackendCapability::JobStreamV1,
    BackendCapability::DurableShareReceiptsV1,
    BackendCapability::EventReplayV1,
    BackendCapability::DualTargetV1,
    BackendCapability::WinnerLifecycleV1,
];

/// One of the independently submitted merged-mining chains.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MergedChain {
    /// The Wcash auxiliary chain.
    Wcash,
    /// The Zcash parent chain.
    Zcash,
}

/// Immutable facts about one exact network-target winner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WinnerDescriptor {
    /// Chain whose target this block satisfies.
    pub chain: MergedChain,
    /// Exact winning block hash in raw little-endian byte order.
    pub block_hash_le: Hex32,
    /// Candidate block height on `chain`.
    pub height: u32,
    /// Coinbase transaction ID in raw little-endian byte order.
    pub coinbase_txid_le: Hex32,
    /// Exact value paid to the configured pool recipient, in zatoshi.
    pub reward_zat: u64,
    /// Confirmations required before this reward becomes spendable.
    pub maturity_confirmations: u32,
}

impl WinnerDescriptor {
    /// Checks bounded immutable winner facts.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero_hex(&self.block_hash_le, "winner.block_hash_le")?;
        if self.height == 0 {
            return Err(invalid("winner.height", "must be positive"));
        }
        require_nonzero_hex(&self.coinbase_txid_le, "winner.coinbase_txid_le")?;
        validate_reward(self.reward_zat, "winner.reward_zat")?;
        validate_maturity(self.maturity_confirmations, "winner.maturity_confirmations")
    }

    /// Checks that immutable reward facts match the generation that produced them.
    pub fn validate_for_job(&self, job: &JobDescriptor) -> Result<(), ProtocolError> {
        job.validate()?;
        self.validate()?;
        let (height, reward, maturity, coinbase_txid) = match self.chain {
            MergedChain::Wcash => (
                job.wcash_height,
                job.wcash_reward_zat,
                job.wcash_maturity_confirmations,
                &job.wcash_coinbase_txid_le,
            ),
            MergedChain::Zcash => (
                job.zcash_height,
                job.zcash_reward_zat,
                job.zcash_maturity_confirmations,
                &job.zcash_coinbase_txid_le,
            ),
        };
        if self.chain == MergedChain::Wcash && self.block_hash_le != job.wcash_candidate_hash_le {
            return Err(invalid(
                "winner.block_hash_le",
                "must match the proof-independent Wcash candidate hash in its job",
            ));
        }
        if &self.coinbase_txid_le != coinbase_txid {
            return Err(invalid(
                "winner.coinbase_txid_le",
                "must match the winning chain coinbase transaction ID in its job",
            ));
        }
        if self.height != height {
            return Err(invalid(
                "winner.height",
                "must match the winning chain height in its job",
            ));
        }
        if self.reward_zat != reward {
            return Err(invalid(
                "winner.reward_zat",
                "must match the winning chain reward in its job",
            ));
        }
        if self.maturity_confirmations != maturity {
            return Err(invalid(
                "winner.maturity_confirmations",
                "must match the winning chain maturity in its job",
            ));
        }
        Ok(())
    }
}

/// Exact best-chain tip sampled while observing one winner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChainTip {
    /// Best-chain tip hash in raw little-endian byte order.
    pub block_hash_le: Hex32,
    /// Best-chain tip height.
    pub height: u32,
}

impl ChainTip {
    fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero_hex(&self.block_hash_le, "winner_tip.block_hash_le")
    }
}

/// Wire representation of an atomic validate-and-journal result.
///
/// This freely constructible value is not proof of a commit by itself. A transport
/// consumer must establish peer policy, request correlation, and protocol validity
/// before treating it as an authoritative receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShareReceipt {
    /// Monotonic sequence of the authoritative journal commit.
    pub event_seq: u64,
    /// Exact backend generation that accepted this share.
    pub job_id: Hex32,
    /// Backend-computed stable share identifier.
    pub share_id: Hex32,
    /// Stable hash of the authenticated worker identity and exact issued target.
    pub attribution_id: Hex32,
    /// Validated parent header hash in raw little-endian byte order.
    pub parent_hash_le: Hex32,
    /// Exact winning blocks durably created with this share.
    ///
    /// Entries are canonical chain order (`wcash`, then `zcash`), contain each
    /// chain at most once, and are empty for an ordinary pool share.
    pub winners: Vec<WinnerDescriptor>,
}

impl ShareReceipt {
    /// Checks receipt identifiers and canonical winner facts.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.event_seq == 0 {
            return Err(invalid("share_receipt.event_seq", "must be positive"));
        }
        require_nonzero_hex(&self.job_id, "share_receipt.job_id")?;
        require_nonzero_hex(&self.share_id, "share_receipt.share_id")?;
        require_nonzero_hex(&self.attribution_id, "share_receipt.attribution_id")?;
        require_nonzero_hex(&self.parent_hash_le, "share_receipt.parent_hash_le")?;
        if self.winners.len() > 2 {
            return Err(invalid(
                "share_receipt.winners",
                "must contain at most one winner per merged chain",
            ));
        }
        let mut previous = None;
        for winner in &self.winners {
            winner.validate()?;
            if previous.is_some_and(|chain| chain >= winner.chain) {
                return Err(invalid(
                    "share_receipt.winners",
                    "must be unique and ordered wcash before zcash",
                ));
            }
            if winner.chain == MergedChain::Zcash && winner.block_hash_le != self.parent_hash_le {
                return Err(invalid(
                    "share_receipt.winners",
                    "zcash winner hash must equal the validated parent header hash",
                ));
            }
            previous = Some(winner.chain);
        }
        Ok(())
    }

    /// Checks that this receipt and all winners belong to one exact generation.
    pub fn validate_for_job(&self, job: &JobDescriptor) -> Result<(), ProtocolError> {
        job.validate()?;
        self.validate()?;
        if self.job_id != job.job_id {
            return Err(invalid(
                "share_receipt.job_id",
                "must match the submitted backend generation",
            ));
        }
        for winner in &self.winners {
            winner.validate_for_job(job)?;
        }
        Ok(())
    }
}

/// One immutable record exposed to the PostgreSQL projection.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackendEvent {
    /// A proposal-validated generation became available.
    JobActivated {
        /// Monotonic backend journal sequence.
        event_seq: u64,
        /// Exact activated work.
        job: JobDescriptor,
    },
    /// A previously advertised generation changed state.
    JobInvalidated {
        /// Monotonic backend journal sequence.
        event_seq: u64,
        /// Exact affected generation.
        job_id: Hex32,
        /// Cause of invalidation.
        reason: JobInvalidationReason,
        /// Bounded grace; zero means immediately stale.
        accept_for_ms: u32,
    },
    /// No later share may be committed to this generation.
    GenerationClosed {
        /// Monotonic backend journal sequence and share-admission close watermark.
        event_seq: u64,
        /// Closed generation.
        job_id: Hex32,
    },
    /// An accepted share was durably attributed.
    ShareCommitted {
        /// Exact backend receipt.
        receipt: ShareReceipt,
        /// Generation that produced the share.
        job_id: Hex32,
        /// Immutable account and worker attribution.
        identity: WorkerIdentity,
        /// Exact target issued for this share, in little-endian numeric order.
        target_le: TargetLe,
    },
    /// A winning block was observed on one chain's current best chain.
    WinnerObserved {
        /// Monotonic backend journal sequence.
        event_seq: u64,
        /// Share whose proof created this winner.
        share_id: Hex32,
        /// Generation that produced the winner.
        job_id: Hex32,
        /// Immutable winning-block and reward facts.
        winner: WinnerDescriptor,
        /// Exact best-chain tip used for this observation.
        tip: ChainTip,
        /// Confirmation count computed from the same state snapshot as `tip`.
        confirmations: u32,
    },
    /// A previously observed winner left one chain's current best chain.
    WinnerOrphaned {
        /// Monotonic backend journal sequence.
        event_seq: u64,
        /// Share whose proof created this winner.
        share_id: Hex32,
        /// Generation that produced the winner.
        job_id: Hex32,
        /// Immutable winning-block and reward facts.
        winner: WinnerDescriptor,
        /// Exact replacement best-chain tip that does not contain the winner.
        tip: ChainTip,
    },
    /// A Wcash winner is quarantined because the best chain contains the same
    /// proof-independent block ID with a different AuxPoW witness.
    ///
    /// The exact submitted and conflicting block bytes remain private to the
    /// backend. The pool must suspend reward progression for this winner until
    /// a later `winner_observed` or `winner_requeued` event resolves the state.
    WinnerQuarantined {
        /// Monotonic backend journal sequence.
        event_seq: u64,
        /// Share whose proof created this winner.
        share_id: Hex32,
        /// Generation that produced the winner.
        job_id: Hex32,
        /// Immutable winning-block and reward facts.
        winner: WinnerDescriptor,
        /// Exact best-chain tip sampled when the witness conflict was found.
        tip: ChainTip,
    },
    /// A quarantined Wcash winner is absent from the current best chain and its
    /// exact retained bytes are eligible for backend-controlled resubmission.
    WinnerRequeued {
        /// Monotonic backend journal sequence.
        event_seq: u64,
        /// Share whose proof created this winner.
        share_id: Hex32,
        /// Generation that produced the winner.
        job_id: Hex32,
        /// Immutable winning-block and reward facts.
        winner: WinnerDescriptor,
        /// Exact best-chain tip sampled before releasing the quarantine.
        tip: ChainTip,
    },
    /// An observed winner reached its chain-specific spendability threshold.
    ///
    /// Maturity is reversible: a later deep reorganization can still emit
    /// `winner_orphaned` for the same winner.
    WinnerMatured {
        /// Monotonic backend journal sequence.
        event_seq: u64,
        /// Share whose proof created this winner.
        share_id: Hex32,
        /// Generation that produced the winner.
        job_id: Hex32,
        /// Immutable winning-block and reward facts.
        winner: WinnerDescriptor,
        /// Exact best-chain tip used for this maturity observation.
        tip: ChainTip,
        /// Confirmation count computed from the same state snapshot as `tip`.
        confirmations: u32,
    },
}

impl fmt::Debug for BackendEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JobActivated { event_seq, job } => formatter
                .debug_struct("JobActivated")
                .field("event_seq", event_seq)
                .field("job", job)
                .finish(),
            Self::JobInvalidated {
                event_seq,
                job_id,
                reason,
                accept_for_ms,
            } => formatter
                .debug_struct("JobInvalidated")
                .field("event_seq", event_seq)
                .field("job_id", job_id)
                .field("reason", reason)
                .field("accept_for_ms", accept_for_ms)
                .finish(),
            Self::GenerationClosed { event_seq, job_id } => formatter
                .debug_struct("GenerationClosed")
                .field("event_seq", event_seq)
                .field("job_id", job_id)
                .finish(),
            Self::ShareCommitted {
                receipt,
                job_id,
                target_le,
                ..
            } => formatter
                .debug_struct("ShareCommitted")
                .field("receipt", receipt)
                .field("job_id", job_id)
                .field("identity", &"[REDACTED]")
                .field("target_le", target_le)
                .finish(),
            Self::WinnerObserved {
                event_seq,
                share_id,
                job_id,
                winner,
                tip,
                confirmations,
            } => formatter
                .debug_struct("WinnerObserved")
                .field("event_seq", event_seq)
                .field("share_id", share_id)
                .field("job_id", job_id)
                .field("winner", winner)
                .field("tip", tip)
                .field("confirmations", confirmations)
                .finish(),
            Self::WinnerOrphaned {
                event_seq,
                share_id,
                job_id,
                winner,
                tip,
            } => formatter
                .debug_struct("WinnerOrphaned")
                .field("event_seq", event_seq)
                .field("share_id", share_id)
                .field("job_id", job_id)
                .field("winner", winner)
                .field("tip", tip)
                .finish(),
            Self::WinnerQuarantined {
                event_seq,
                share_id,
                job_id,
                winner,
                tip,
            } => formatter
                .debug_struct("WinnerQuarantined")
                .field("event_seq", event_seq)
                .field("share_id", share_id)
                .field("job_id", job_id)
                .field("winner", winner)
                .field("tip", tip)
                .finish(),
            Self::WinnerRequeued {
                event_seq,
                share_id,
                job_id,
                winner,
                tip,
            } => formatter
                .debug_struct("WinnerRequeued")
                .field("event_seq", event_seq)
                .field("share_id", share_id)
                .field("job_id", job_id)
                .field("winner", winner)
                .field("tip", tip)
                .finish(),
            Self::WinnerMatured {
                event_seq,
                share_id,
                job_id,
                winner,
                tip,
                confirmations,
            } => formatter
                .debug_struct("WinnerMatured")
                .field("event_seq", event_seq)
                .field("share_id", share_id)
                .field("job_id", job_id)
                .field("winner", winner)
                .field("tip", tip)
                .field("confirmations", confirmations)
                .finish(),
        }
    }
}

impl BackendEvent {
    /// Returns the event's authoritative journal sequence.
    pub const fn event_seq(&self) -> u64 {
        match self {
            Self::JobActivated { event_seq, .. }
            | Self::JobInvalidated { event_seq, .. }
            | Self::GenerationClosed { event_seq, .. }
            | Self::WinnerObserved { event_seq, .. }
            | Self::WinnerOrphaned { event_seq, .. }
            | Self::WinnerQuarantined { event_seq, .. }
            | Self::WinnerRequeued { event_seq, .. }
            | Self::WinnerMatured { event_seq, .. } => *event_seq,
            Self::ShareCommitted { receipt, .. } => receipt.event_seq,
        }
    }

    /// Checks event-specific bounds and nested wire values.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.event_seq() == 0 {
            return Err(invalid("event.event_seq", "must be positive"));
        }
        match self {
            Self::JobActivated { job, .. } => job.validate(),
            Self::JobInvalidated {
                job_id,
                reason,
                accept_for_ms,
                ..
            } => {
                require_nonzero_hex(job_id, "event.job_id")?;
                match reason {
                    JobInvalidationReason::WcashTipChanged
                    | JobInvalidationReason::ZcashTipChanged => {
                        if *accept_for_ms != 0 {
                            return Err(invalid(
                                "event.accept_for_ms",
                                "tip changes must be immediately stale",
                            ));
                        }
                    }
                    JobInvalidationReason::Superseded => {
                        if !(1..=60_000).contains(accept_for_ms) {
                            return Err(invalid(
                                "event.accept_for_ms",
                                "superseded work needs 1..=60000 milliseconds of grace",
                            ));
                        }
                    }
                    JobInvalidationReason::Age => {
                        if *accept_for_ms != 0 {
                            return Err(invalid(
                                "event.accept_for_ms",
                                "age-expired work must be immediately stale",
                            ));
                        }
                    }
                }
                Ok(())
            }
            Self::GenerationClosed { job_id, .. } => require_nonzero_hex(job_id, "event.job_id"),
            Self::ShareCommitted {
                receipt,
                job_id,
                identity,
                target_le,
            } => {
                receipt.validate()?;
                require_nonzero_hex(job_id, "event.job_id")?;
                if receipt.job_id != *job_id {
                    return Err(invalid("event.job_id", "must match share_receipt.job_id"));
                }
                if receipt.attribution_id != canonical_attribution_id(identity, target_le)? {
                    return Err(invalid(
                        "event.attribution",
                        "must match share_receipt.attribution_id",
                    ));
                }
                identity.validate()?;
                require_nonzero_target(target_le, "event.target_le")
            }
            Self::WinnerObserved {
                share_id,
                job_id,
                winner,
                tip,
                confirmations,
                ..
            } => validate_winner_observation(share_id, job_id, winner, tip, *confirmations, false),
            Self::WinnerOrphaned {
                share_id,
                job_id,
                winner,
                tip,
                ..
            } => validate_winner_orphan(share_id, job_id, winner, tip),
            Self::WinnerQuarantined {
                share_id,
                job_id,
                winner,
                tip,
                ..
            } => validate_wcash_winner_quarantine(share_id, job_id, winner, tip),
            Self::WinnerRequeued {
                share_id,
                job_id,
                winner,
                tip,
                ..
            } => validate_wcash_winner_requeue(share_id, job_id, winner, tip),
            Self::WinnerMatured {
                share_id,
                job_id,
                winner,
                tip,
                confirmations,
                ..
            } => validate_winner_observation(share_id, job_id, winner, tip, *confirmations, true),
        }
    }
}

/// Messages sent from the pool edge to the local consensus backend.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackendRequest {
    /// Negotiates protocol and chain identity before any other request.
    Hello {
        /// Protocol version; must be one.
        #[serde(rename = "v")]
        version: u16,
        /// Nonzero connection-local request identifier.
        id: u64,
        /// Stable identity of this pool-edge process.
        pool_instance: CanonicalUuid,
        /// Last event already projected by this edge.
        last_event_seq: u64,
    },
    /// Requests an atomic current/recent job snapshot followed by events.
    SubscribeJobs {
        /// Protocol version; must be one.
        #[serde(rename = "v")]
        version: u16,
        /// Nonzero connection-local request identifier.
        id: u64,
        /// Last job event already observed by this edge.
        after_event_seq: u64,
    },
    /// Validates and durably commits one fully reconstructed share.
    SubmitShare {
        /// Protocol version; must be one.
        #[serde(rename = "v")]
        version: u16,
        /// Nonzero connection-local request identifier.
        id: u64,
        /// Exact backend generation advertised to the miner.
        job_id: Hex32,
        /// Canonical identity resolved by the authenticated edge session.
        identity: WorkerIdentity,
        /// Exact per-job target issued to this miner, little-endian numeric.
        target_le: TargetLe,
        /// Exact four raw header-time bytes issued in the frozen job.
        time: Hex4,
        /// Full 32-byte header nonce after prefix reconstruction.
        nonce: Hex32,
        /// Raw 1,344-byte Equihash solution without CompactSize.
        solution: Box<Hex1344>,
    },
    /// Reads a bounded page for idempotent database projection.
    ReadEvents {
        /// Protocol version; must be one.
        #[serde(rename = "v")]
        version: u16,
        /// Nonzero connection-local request identifier.
        id: u64,
        /// Exclusive journal cursor.
        after_event_seq: u64,
        /// Positive bounded number of events requested.
        limit: u16,
    },
    /// Requests a bounded health snapshot.
    Health {
        /// Protocol version; must be one.
        #[serde(rename = "v")]
        version: u16,
        /// Nonzero connection-local request identifier.
        id: u64,
    },
}

impl fmt::Debug for BackendRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hello {
                version,
                id,
                pool_instance,
                last_event_seq,
            } => formatter
                .debug_struct("Hello")
                .field("version", version)
                .field("id", id)
                .field("pool_instance", pool_instance)
                .field("last_event_seq", last_event_seq)
                .finish(),
            Self::SubscribeJobs {
                version,
                id,
                after_event_seq,
            } => formatter
                .debug_struct("SubscribeJobs")
                .field("version", version)
                .field("id", id)
                .field("after_event_seq", after_event_seq)
                .finish(),
            Self::SubmitShare {
                version,
                id,
                job_id,
                target_le,
                time,
                ..
            } => formatter
                .debug_struct("SubmitShare")
                .field("version", version)
                .field("id", id)
                .field("job_id", job_id)
                .field("identity", &"[REDACTED]")
                .field("target_le", target_le)
                .field("time", time)
                .field("nonce", &"[REDACTED]")
                .field("solution", &"[REDACTED 1344 bytes]")
                .finish(),
            Self::ReadEvents {
                version,
                id,
                after_event_seq,
                limit,
            } => formatter
                .debug_struct("ReadEvents")
                .field("version", version)
                .field("id", id)
                .field("after_event_seq", after_event_seq)
                .field("limit", limit)
                .finish(),
            Self::Health { version, id } => formatter
                .debug_struct("Health")
                .field("version", version)
                .field("id", id)
                .finish(),
        }
    }
}

impl BackendRequest {
    /// Returns the connection-local correlation ID.
    pub const fn id(&self) -> u64 {
        match self {
            Self::Hello { id, .. }
            | Self::SubscribeJobs { id, .. }
            | Self::SubmitShare { id, .. }
            | Self::ReadEvents { id, .. }
            | Self::Health { id, .. } => *id,
        }
    }

    /// Checks protocol version, IDs, and request-specific invariants.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        let (version, id) = match self {
            Self::Hello { version, id, .. }
            | Self::SubscribeJobs { version, id, .. }
            | Self::SubmitShare { version, id, .. }
            | Self::ReadEvents { version, id, .. }
            | Self::Health { version, id } => (*version, *id),
        };
        validate_backend_header(version, id)?;
        match self {
            Self::Hello { pool_instance, .. } => {
                require_non_nil_uuid(pool_instance, "hello.pool_instance")
            }
            Self::SubmitShare {
                job_id,
                identity,
                target_le,
                time,
                ..
            } => {
                require_nonzero_hex(job_id, "submit_share.job_id")?;
                identity.validate()?;
                require_nonzero_target(target_le, "submit_share.target_le")?;
                require_nonzero_hex(time, "submit_share.time")
            }
            Self::ReadEvents { limit, .. } if !(1..=MAX_EVENT_PAGE_ITEMS).contains(limit) => {
                Err(invalid(
                    "read_events.limit",
                    format!("must be in 1..={MAX_EVENT_PAGE_ITEMS}"),
                ))
            }
            _ => Ok(()),
        }
    }
}

/// Messages returned or streamed by the local consensus backend.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackendMessage {
    /// Successful protocol and network identity negotiation.
    HelloOk {
        /// Protocol version; must be one.
        #[serde(rename = "v")]
        version: u16,
        /// Request identifier copied from `hello`.
        id: u64,
        /// Unique backend connection/session identity.
        backend_session: CanonicalUuid,
        /// Stable identity of the backend installation across reconnects.
        backend_instance: CanonicalUuid,
        /// Stable identity of the journal sequence namespace.
        journal_stream: CanonicalUuid,
        /// Explicit features implemented by this backend connection.
        capabilities: Vec<BackendCapability>,
        /// Pinned Wcash genesis block hash in raw byte order.
        wcash_genesis: Hex32,
        /// Pinned Zcash genesis block hash in raw byte order.
        zcash_genesis: Hex32,
        /// Domain-separated commitment to the exact Wcash block-reward recipient.
        wcash_payout_commitment: Hex32,
        /// Domain-separated commitment to the exact Zcash block-reward recipient.
        zcash_payout_commitment: Hex32,
        /// Wcash AuxPoW chain identifier.
        chain_id: u32,
        /// Latest durable event sequence.
        current_event_seq: u64,
    },
    /// Atomic state returned before live job events begin.
    JobSnapshot {
        /// Protocol version; must be one.
        #[serde(rename = "v")]
        version: u16,
        /// Request identifier copied from `subscribe_jobs`.
        id: u64,
        /// Snapshot journal watermark.
        event_seq: u64,
        /// Current job, or none while mining is safely paused.
        current: Option<AcceptableJob>,
        /// At most two still-acceptable prior generations.
        recent: Vec<AcceptableJob>,
    },
    /// Atomic durable share acknowledgement.
    ShareCommitted {
        /// Protocol version; must be one.
        #[serde(rename = "v")]
        version: u16,
        /// Request identifier copied from `submit_share`.
        id: u64,
        /// Exact commit receipt.
        receipt: ShareReceipt,
        /// Whether this response returned an already-durable identical commit.
        replayed: bool,
    },
    /// Bounded authoritative journal page.
    EventsPage {
        /// Protocol version; must be one.
        #[serde(rename = "v")]
        version: u16,
        /// Request identifier copied from `read_events`.
        id: u64,
        /// Exclusive cursor from the request.
        after_event_seq: u64,
        /// Last sequence included, or the input cursor for an empty page.
        next_event_seq: u64,
        /// Whether the page reached the current durable journal end.
        complete: bool,
        /// Strictly ordered immutable events.
        events: Vec<BackendEvent>,
    },
    /// Backend health and winner-outbox pressure.
    HealthStatus {
        /// Protocol version; must be one.
        #[serde(rename = "v")]
        version: u16,
        /// Request identifier copied from `health`.
        id: u64,
        /// Latest durable event sequence.
        event_seq: u64,
        /// True only while the backend can accept shares safely.
        healthy: bool,
        /// Wcash winners retained in the durable outbox.
        pending_wcash: u32,
        /// Pending Wcash winners held behind conflicting-witness quarantine.
        quarantined_wcash: u32,
        /// Zcash winners retained in the durable outbox.
        pending_zcash: u32,
    },
    /// Typed request failure without secret-bearing diagnostics.
    Error {
        /// Protocol version; must be one.
        #[serde(rename = "v")]
        version: u16,
        /// Request identifier, or zero when no valid ID was recoverable.
        id: u64,
        /// Stable machine-readable failure category.
        code: BackendErrorCode,
        /// Bounded printable operator detail.
        message: String,
    },
    /// Unsolicited or paginated journal event.
    Event {
        /// Protocol version; must be one.
        #[serde(rename = "v")]
        version: u16,
        /// Exact durable event.
        event: BackendEvent,
    },
}

impl fmt::Debug for BackendMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HelloOk {
                version,
                id,
                backend_session,
                backend_instance,
                journal_stream,
                capabilities,
                wcash_genesis,
                zcash_genesis,
                wcash_payout_commitment,
                zcash_payout_commitment,
                chain_id,
                current_event_seq,
            } => formatter
                .debug_struct("HelloOk")
                .field("version", version)
                .field("id", id)
                .field("backend_session", backend_session)
                .field("backend_instance", backend_instance)
                .field("journal_stream", journal_stream)
                .field("capabilities", capabilities)
                .field("wcash_genesis", wcash_genesis)
                .field("zcash_genesis", zcash_genesis)
                .field("wcash_payout_commitment", wcash_payout_commitment)
                .field("zcash_payout_commitment", zcash_payout_commitment)
                .field("chain_id", chain_id)
                .field("current_event_seq", current_event_seq)
                .finish(),
            Self::JobSnapshot {
                version,
                id,
                event_seq,
                current,
                recent,
            } => formatter
                .debug_struct("JobSnapshot")
                .field("version", version)
                .field("id", id)
                .field("event_seq", event_seq)
                .field("current", current)
                .field("recent", recent)
                .finish(),
            Self::ShareCommitted {
                version,
                id,
                receipt,
                replayed,
            } => formatter
                .debug_struct("ShareCommitted")
                .field("version", version)
                .field("id", id)
                .field("receipt", receipt)
                .field("replayed", replayed)
                .finish(),
            Self::EventsPage {
                version,
                id,
                after_event_seq,
                next_event_seq,
                complete,
                events,
            } => formatter
                .debug_struct("EventsPage")
                .field("version", version)
                .field("id", id)
                .field("after_event_seq", after_event_seq)
                .field("next_event_seq", next_event_seq)
                .field("complete", complete)
                .field("events", events)
                .finish(),
            Self::HealthStatus {
                version,
                id,
                event_seq,
                healthy,
                pending_wcash,
                quarantined_wcash,
                pending_zcash,
            } => formatter
                .debug_struct("HealthStatus")
                .field("version", version)
                .field("id", id)
                .field("event_seq", event_seq)
                .field("healthy", healthy)
                .field("pending_wcash", pending_wcash)
                .field("quarantined_wcash", quarantined_wcash)
                .field("pending_zcash", pending_zcash)
                .finish(),
            Self::Error {
                version, id, code, ..
            } => formatter
                .debug_struct("Error")
                .field("version", version)
                .field("id", id)
                .field("code", code)
                .field("message", &"[REDACTED]")
                .finish(),
            Self::Event { version, event } => formatter
                .debug_struct("Event")
                .field("version", version)
                .field("event", event)
                .finish(),
        }
    }
}

impl BackendMessage {
    /// Returns the request correlation ID, or `None` for an unsolicited event.
    pub const fn correlation_id(&self) -> Option<u64> {
        match self {
            Self::HelloOk { id, .. }
            | Self::JobSnapshot { id, .. }
            | Self::ShareCommitted { id, .. }
            | Self::EventsPage { id, .. }
            | Self::HealthStatus { id, .. }
            | Self::Error { id, .. } => Some(*id),
            Self::Event { .. } => None,
        }
    }

    /// Checks protocol version, correlation IDs, page ordering, and nested data.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        let version = match self {
            Self::HelloOk { version, .. }
            | Self::JobSnapshot { version, .. }
            | Self::ShareCommitted { version, .. }
            | Self::EventsPage { version, .. }
            | Self::HealthStatus { version, .. }
            | Self::Error { version, .. }
            | Self::Event { version, .. } => *version,
        };
        if version != BACKEND_PROTOCOL_VERSION {
            return Err(invalid(
                "backend.v",
                format!("must equal {BACKEND_PROTOCOL_VERSION}"),
            ));
        }
        match self {
            Self::HelloOk {
                id,
                backend_session,
                backend_instance,
                journal_stream,
                capabilities,
                wcash_genesis,
                zcash_genesis,
                wcash_payout_commitment,
                zcash_payout_commitment,
                chain_id,
                ..
            } => {
                require_nonzero_id(*id)?;
                require_non_nil_uuid(backend_session, "hello_ok.backend_session")?;
                require_non_nil_uuid(backend_instance, "hello_ok.backend_instance")?;
                require_non_nil_uuid(journal_stream, "hello_ok.journal_stream")?;
                if backend_session == backend_instance
                    || backend_session == journal_stream
                    || backend_instance == journal_stream
                {
                    return Err(invalid(
                        "hello_ok identities",
                        "session, backend instance, and journal stream must be distinct",
                    ));
                }
                if capabilities.len() != REQUIRED_BACKEND_CAPABILITIES.len()
                    || capabilities
                        .iter()
                        .enumerate()
                        .any(|(index, capability)| capabilities[..index].contains(capability))
                    || REQUIRED_BACKEND_CAPABILITIES
                        .iter()
                        .any(|required| !capabilities.contains(required))
                {
                    return Err(invalid(
                        "hello_ok.capabilities",
                        "must contain every protocol-v1 capability exactly once",
                    ));
                }
                require_nonzero_hex(wcash_genesis, "hello_ok.wcash_genesis")?;
                require_nonzero_hex(zcash_genesis, "hello_ok.zcash_genesis")?;
                require_nonzero_hex(wcash_payout_commitment, "hello_ok.wcash_payout_commitment")?;
                require_nonzero_hex(zcash_payout_commitment, "hello_ok.zcash_payout_commitment")?;
                if *chain_id == 0 {
                    return Err(invalid("hello_ok.chain_id", "must be nonzero"));
                }
                Ok(())
            }
            Self::JobSnapshot {
                id,
                current,
                recent,
                ..
            } => {
                require_nonzero_id(*id)?;
                if recent.len() > 2 {
                    return Err(invalid(
                        "job_snapshot.recent",
                        "must contain at most two jobs",
                    ));
                }
                if let Some(current) = current {
                    current.validate()?;
                }
                for job in recent {
                    job.validate()?;
                }
                let mut ids = Vec::with_capacity(recent.len() + usize::from(current.is_some()));
                if let Some(current) = current {
                    ids.push(current.job.job_id.as_bytes());
                }
                ids.extend(recent.iter().map(|entry| entry.job.job_id.as_bytes()));
                if ids
                    .iter()
                    .enumerate()
                    .any(|(index, id)| ids[..index].contains(id))
                {
                    return Err(invalid(
                        "job_snapshot",
                        "contains the same job more than once",
                    ));
                }
                Ok(())
            }
            Self::ShareCommitted { id, receipt, .. } => {
                require_nonzero_id(*id)?;
                receipt.validate()
            }
            Self::EventsPage {
                id,
                after_event_seq,
                next_event_seq,
                complete,
                events,
                ..
            } => {
                require_nonzero_id(*id)?;
                if events.len() > usize::from(MAX_EVENT_PAGE_ITEMS) {
                    return Err(invalid(
                        "events_page.events",
                        format!("must contain at most {MAX_EVENT_PAGE_ITEMS} events"),
                    ));
                }
                if !complete && events.is_empty() {
                    return Err(invalid(
                        "events_page.events",
                        "an incomplete page must advance with at least one event",
                    ));
                }
                let mut previous = *after_event_seq;
                for event in events {
                    event.validate()?;
                    let expected = previous.checked_add(1).ok_or_else(|| {
                        invalid(
                            "events_page.events",
                            "event sequence overflowed after the cursor",
                        )
                    })?;
                    if event.event_seq() != expected {
                        return Err(invalid(
                            "events_page.events",
                            "event sequences must be contiguous after the cursor",
                        ));
                    }
                    previous = event.event_seq();
                }
                if *next_event_seq != previous {
                    return Err(invalid(
                        "events_page.next_event_seq",
                        "must equal the final event sequence or the empty-page cursor",
                    ));
                }
                Ok(())
            }
            Self::HealthStatus {
                id,
                pending_wcash,
                quarantined_wcash,
                ..
            } => {
                require_nonzero_id(*id)?;
                if quarantined_wcash > pending_wcash {
                    return Err(invalid(
                        "health_status.quarantined_wcash",
                        "must not exceed pending_wcash",
                    ));
                }
                Ok(())
            }
            Self::Error { id, message, .. } => {
                if *id != 0 {
                    require_nonzero_id(*id)?;
                }
                validate_bounded_text(message, 1, 512, "error.message")
            }
            Self::Event { event, .. } => event.validate(),
        }
    }
}

/// Serializes one validated backend request with its exact length prefix.
pub fn encode_backend_request(request: &BackendRequest) -> Result<Vec<u8>, ProtocolError> {
    request.validate()?;
    encode_length_frame(request)
}

/// Decodes one complete backend request and rejects trailing bytes.
pub fn decode_backend_request(frame: &[u8]) -> Result<BackendRequest, ProtocolError> {
    let request: BackendRequest = decode_length_frame(frame)?;
    request.validate()?;
    Ok(request)
}

/// Serializes one validated backend response or event with its exact length prefix.
pub fn encode_backend_message(message: &BackendMessage) -> Result<Vec<u8>, ProtocolError> {
    message.validate()?;
    encode_length_frame(message)
}

/// Decodes one complete backend response or event and rejects trailing bytes.
pub fn decode_backend_message(frame: &[u8]) -> Result<BackendMessage, ProtocolError> {
    let message: BackendMessage = decode_length_frame(frame)?;
    message.validate()?;
    Ok(message)
}

/// Transport-facing name for a message sent to the backend.
pub type ClientMessage = BackendRequest;

/// Transport-facing name for a message sent by the backend.
pub type ServerMessage = BackendMessage;

/// Structured share submission used by transport adapters.
///
/// Convert this value into ClientMessage before encoding it. Keeping the
/// fields in a named type lets callers construct and test submissions without
/// duplicating the consensus-sensitive wire field set.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitShare {
    /// Protocol version; must equal BACKEND_PROTOCOL_VERSION.
    #[serde(rename = "v")]
    pub version: u16,
    /// Nonzero connection-local request identifier.
    pub id: u64,
    /// Exact backend generation advertised to the miner.
    pub job_id: Hex32,
    /// Canonical identity resolved by the authenticated edge session.
    pub identity: WorkerIdentity,
    /// Exact per-job target issued to this miner, little-endian numeric.
    pub target_le: TargetLe,
    /// Exact four raw header-time bytes issued in the frozen job.
    pub time: Hex4,
    /// Full 32-byte header nonce after prefix reconstruction.
    pub nonce: Hex32,
    /// Raw 1,344-byte Equihash solution without CompactSize.
    pub solution: Box<Hex1344>,
}

impl fmt::Debug for SubmitShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubmitShare")
            .field("version", &self.version)
            .field("id", &self.id)
            .field("job_id", &self.job_id)
            .field("identity", &"[REDACTED]")
            .field("target_le", &self.target_le)
            .field("time", &self.time)
            .field("nonce", &"[REDACTED]")
            .field("solution", &"[REDACTED 1344 bytes]")
            .finish()
    }
}

impl SubmitShare {
    /// Checks all submission fields without encoding the request.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_backend_header(self.version, self.id)?;
        require_nonzero_hex(&self.job_id, "submit_share.job_id")?;
        self.identity.validate()?;
        require_nonzero_target(&self.target_le, "submit_share.target_le")?;
        require_nonzero_hex(&self.time, "submit_share.time")
    }
}

impl From<SubmitShare> for BackendRequest {
    fn from(submission: SubmitShare) -> Self {
        Self::SubmitShare {
            version: submission.version,
            id: submission.id,
            job_id: submission.job_id,
            identity: submission.identity,
            target_le: submission.target_le,
            time: submission.time,
            nonce: submission.nonce,
            solution: submission.solution,
        }
    }
}

/// Incremental decoder for the backend's bounded four-byte length framing.
///
/// Use a separate codec per transport direction. FrameCodec::decode_client
/// and FrameCodec::decode_server consume at most one complete frame and report
/// exactly how many input bytes were consumed, so callers can loop over
/// coalesced frames without copying them. The declared payload length is
/// checked before any payload reservation.
#[derive(Debug, Default)]
pub struct FrameCodec {
    prefix: [u8; BACKEND_LENGTH_PREFIX_BYTES],
    prefix_len: usize,
    declared: Option<usize>,
    payload: Vec<u8>,
}

impl FrameCodec {
    /// Creates an empty backend frame decoder.
    pub const fn new() -> Self {
        Self {
            prefix: [0; BACKEND_LENGTH_PREFIX_BYTES],
            prefix_len: 0,
            declared: None,
            payload: Vec::new(),
        }
    }

    /// Encodes one validated client message.
    pub fn encode_client(message: &ClientMessage) -> Result<Vec<u8>, ProtocolError> {
        encode_backend_request(message)
    }

    /// Encodes one validated server response or event.
    pub fn encode_server(message: &ServerMessage) -> Result<Vec<u8>, ProtocolError> {
        encode_backend_message(message)
    }

    /// Incrementally decodes at most one client message.
    ///
    /// The returned byte count can be smaller than the input length when the
    /// input also contains a subsequent frame.
    pub fn decode_client(
        &mut self,
        input: &[u8],
    ) -> Result<(usize, Option<ClientMessage>), ProtocolError> {
        self.decode_one(input, BackendRequest::validate)
    }

    /// Incrementally decodes at most one server response or event.
    ///
    /// The returned byte count can be smaller than the input length when the
    /// input also contains a subsequent frame.
    pub fn decode_server(
        &mut self,
        input: &[u8],
    ) -> Result<(usize, Option<ServerMessage>), ProtocolError> {
        self.decode_one(input, BackendMessage::validate)
    }

    /// Discards an incomplete frame, for example after replacing a transport.
    pub fn reset(&mut self) {
        self.prefix = [0; BACKEND_LENGTH_PREFIX_BYTES];
        self.prefix_len = 0;
        self.declared = None;
        self.payload.clear();
    }

    /// Returns bytes currently retained from an incomplete frame.
    pub fn buffered_bytes(&self) -> usize {
        self.prefix_len + self.payload.len()
    }

    fn decode_one<T>(
        &mut self,
        input: &[u8],
        validate: fn(&T) -> Result<(), ProtocolError>,
    ) -> Result<(usize, Option<T>), ProtocolError>
    where
        T: DeserializeOwned,
    {
        let mut consumed = 0usize;

        if self.declared.is_none() {
            let required = BACKEND_LENGTH_PREFIX_BYTES.saturating_sub(self.prefix_len);
            let copied = required.min(input.len());
            let prefix_end = self
                .prefix_len
                .checked_add(copied)
                .ok_or_else(|| invalid("backend decoder", "prefix length overflowed"))?;
            let destination = self
                .prefix
                .get_mut(self.prefix_len..prefix_end)
                .ok_or_else(|| invalid("backend decoder", "prefix state was inconsistent"))?;
            let source = input
                .get(..copied)
                .ok_or_else(|| invalid("backend decoder", "input state was inconsistent"))?;
            destination.copy_from_slice(source);
            self.prefix_len = prefix_end;
            consumed = copied;

            if self.prefix_len < BACKEND_LENGTH_PREFIX_BYTES {
                return Ok((consumed, None));
            }

            let declared = u32::from_be_bytes(self.prefix) as usize;
            if declared == 0 {
                self.reset();
                return Err(ProtocolError::EmptyFrame {
                    protocol: "backend",
                });
            }
            if declared > MAX_BACKEND_PAYLOAD_BYTES {
                self.reset();
                return Err(ProtocolError::FrameTooLarge {
                    protocol: "backend",
                    maximum: MAX_BACKEND_PAYLOAD_BYTES,
                    actual: declared,
                });
            }
            if self.payload.try_reserve_exact(declared).is_err() {
                self.reset();
                return Err(invalid(
                    "backend decoder",
                    "could not reserve bounded payload",
                ));
            }
            self.declared = Some(declared);
        }

        let declared = self
            .declared
            .ok_or_else(|| invalid("backend decoder", "declared length was not initialized"))?;
        let remaining = declared
            .checked_sub(self.payload.len())
            .ok_or_else(|| invalid("backend decoder", "payload exceeded declared length"))?;
        let available = input
            .get(consumed..)
            .ok_or_else(|| invalid("backend decoder", "input cursor exceeded input length"))?;
        let copied = remaining.min(available.len());
        let source = available
            .get(..copied)
            .ok_or_else(|| invalid("backend decoder", "input state was inconsistent"))?;
        self.payload.extend_from_slice(source);
        consumed = consumed
            .checked_add(copied)
            .ok_or_else(|| invalid("backend decoder", "consumed length overflowed"))?;

        if self.payload.len() < declared {
            return Ok((consumed, None));
        }

        let decoded = serde_json::from_slice(&self.payload)
            .map_err(|error| ProtocolError::Json(error.to_string()));
        self.reset();
        let message = decoded?;
        validate(&message)?;
        Ok((consumed, Some(message)))
    }
}

fn validate_backend_header(version: u16, id: u64) -> Result<(), ProtocolError> {
    if version != BACKEND_PROTOCOL_VERSION {
        return Err(invalid(
            "backend.v",
            format!("must equal {BACKEND_PROTOCOL_VERSION}"),
        ));
    }
    require_nonzero_id(id)
}

fn require_nonzero_id(id: u64) -> Result<(), ProtocolError> {
    if id == 0 {
        return Err(invalid("backend.id", "must be nonzero"));
    }
    Ok(())
}

fn require_non_nil_uuid(value: &CanonicalUuid, field: &'static str) -> Result<(), ProtocolError> {
    if value.is_nil() {
        return Err(invalid(field, "must not be the nil UUID"));
    }
    Ok(())
}

fn require_nonzero_target(value: &TargetLe, field: &'static str) -> Result<(), ProtocolError> {
    if value.is_zero() {
        return Err(invalid(field, "must be nonzero"));
    }
    Ok(())
}

fn validate_reward(value: u64, field: &'static str) -> Result<(), ProtocolError> {
    if value > MAX_CHAIN_VALUE_ZAT {
        return Err(invalid(
            field,
            format!("must be no greater than {MAX_CHAIN_VALUE_ZAT} zatoshi"),
        ));
    }
    Ok(())
}

fn validate_maturity(value: u32, field: &'static str) -> Result<(), ProtocolError> {
    if !(1..=MAX_MATURITY_CONFIRMATIONS).contains(&value) {
        return Err(invalid(
            field,
            format!("must be in 1..={MAX_MATURITY_CONFIRMATIONS}"),
        ));
    }
    Ok(())
}

fn validate_winner_reference(
    share_id: &Hex32,
    job_id: &Hex32,
    winner: &WinnerDescriptor,
) -> Result<(), ProtocolError> {
    require_nonzero_hex(share_id, "winner_event.share_id")?;
    require_nonzero_hex(job_id, "winner_event.job_id")?;
    winner.validate()
}

fn validate_winner_observation(
    share_id: &Hex32,
    job_id: &Hex32,
    winner: &WinnerDescriptor,
    tip: &ChainTip,
    confirmations: u32,
    matured: bool,
) -> Result<(), ProtocolError> {
    validate_winner_reference(share_id, job_id, winner)?;
    tip.validate()?;
    let tip_is_winner = tip.block_hash_le == winner.block_hash_le;
    let tip_is_at_winner_height = tip.height == winner.height;
    if tip_is_winner != tip_is_at_winner_height {
        return Err(invalid(
            "winner_event.tip",
            "tip hash must equal the winner hash exactly at the winner height",
        ));
    }
    let expected = tip
        .height
        .checked_sub(winner.height)
        .and_then(|depth| depth.checked_add(1))
        .ok_or_else(|| {
            invalid(
                "winner_event.confirmations",
                "tip height must be at or above the winner height",
            )
        })?;
    if confirmations != expected {
        return Err(invalid(
            "winner_event.confirmations",
            "must equal tip height minus winner height plus one",
        ));
    }
    if matured && confirmations < winner.maturity_confirmations {
        return Err(invalid(
            "winner_event.confirmations",
            "matured winner has not reached its immutable confirmation requirement",
        ));
    }
    Ok(())
}

fn validate_winner_orphan(
    share_id: &Hex32,
    job_id: &Hex32,
    winner: &WinnerDescriptor,
    tip: &ChainTip,
) -> Result<(), ProtocolError> {
    validate_winner_reference(share_id, job_id, winner)?;
    tip.validate()?;
    if tip.block_hash_le == winner.block_hash_le {
        return Err(invalid(
            "winner_event.tip",
            "orphan replacement tip must not be the winning block",
        ));
    }
    Ok(())
}

fn validate_wcash_winner_quarantine(
    share_id: &Hex32,
    job_id: &Hex32,
    winner: &WinnerDescriptor,
    tip: &ChainTip,
) -> Result<(), ProtocolError> {
    validate_wcash_winner_transition(share_id, job_id, winner, tip)?;
    let tip_is_winner = tip.block_hash_le == winner.block_hash_le;
    let tip_is_at_winner_height = tip.height == winner.height;
    if tip.height < winner.height {
        return Err(invalid(
            "winner_event.tip",
            "quarantine tip must be at or above the Wcash winner height",
        ));
    }
    if tip_is_winner != tip_is_at_winner_height {
        return Err(invalid(
            "winner_event.tip",
            "tip hash must equal the Wcash winner ID exactly at its height",
        ));
    }
    Ok(())
}

fn validate_wcash_winner_requeue(
    share_id: &Hex32,
    job_id: &Hex32,
    winner: &WinnerDescriptor,
    tip: &ChainTip,
) -> Result<(), ProtocolError> {
    validate_wcash_winner_transition(share_id, job_id, winner, tip)?;
    if tip.block_hash_le == winner.block_hash_le {
        return Err(invalid(
            "winner_event.tip",
            "requeue tip must not be the quarantined Wcash winner",
        ));
    }
    Ok(())
}

fn validate_wcash_winner_transition(
    share_id: &Hex32,
    job_id: &Hex32,
    winner: &WinnerDescriptor,
    tip: &ChainTip,
) -> Result<(), ProtocolError> {
    validate_winner_reference(share_id, job_id, winner)?;
    if winner.chain != MergedChain::Wcash {
        return Err(invalid(
            "winner_event.winner.chain",
            "conflicting-witness quarantine is Wcash-only",
        ));
    }
    tip.validate()
}

pub(crate) fn require_nonzero_hex<const N: usize>(
    value: &FixedHex<N>,
    field: &'static str,
) -> Result<(), ProtocolError> {
    if value.is_zero() {
        return Err(invalid(field, "must be nonzero"));
    }
    Ok(())
}

pub(crate) fn validate_worker_label(label: &str) -> Result<(), ProtocolError> {
    validate_bounded_text(label, 1, 128, "worker.label")?;
    if !label
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
    {
        return Err(invalid(
            "worker.label",
            "must use ASCII letters, digits, '.', '-', '_', or ':'",
        ));
    }
    Ok(())
}

pub(crate) fn validate_bounded_text(
    value: &str,
    minimum: usize,
    maximum: usize,
    field: &'static str,
) -> Result<(), ProtocolError> {
    if !(minimum..=maximum).contains(&value.len()) {
        return Err(invalid(
            field,
            format!("must contain {minimum}..={maximum} bytes"),
        ));
    }
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(invalid(field, "must not contain control bytes"));
    }
    Ok(())
}
