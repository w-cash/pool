//! Explicit boundary to an isolated Testnet wallet signer.
//!
//! This module does not contain spending keys or a software wallet. It defines
//! the fail-closed contract that the durable accounting projector may call
//! after reconciling a mature payout batch.

use std::{collections::HashSet, fmt, sync::Arc};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{Asset, ChainNetwork, ReceiverKind};

/// Maximum outputs permitted in one signer request.
pub const MAX_PAYOUT_OUTPUTS: usize = 200;
const PAYOUT_COMMITMENT_DOMAIN: &[u8] = b"zecwec/payout-batch/v1";

/// One exact payout output authorized by the accounting projector.
#[derive(Clone, Eq, PartialEq)]
pub struct PayoutOutput {
    /// Stable ledger allocation identifier.
    pub allocation_id: Uuid,
    /// Canonical address previously validated for this asset and network.
    pub canonical_address: String,
    /// Validated receiver class.
    pub receiver_kind: ReceiverKind,
    /// Exact atomic-unit amount.
    pub amount_zat: u64,
}

impl fmt::Debug for PayoutOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PayoutOutput")
            .field("allocation_id", &self.allocation_id)
            .field("canonical_address", &"[REDACTED]")
            .field("receiver_kind", &self.receiver_kind)
            .field("amount_zat", &self.amount_zat)
            .finish()
    }
}

/// Complete idempotent request to the isolated signer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayoutBatchRequest {
    /// Stable idempotency key. A retry uses the exact same identifier.
    pub batch_id: Uuid,
    /// Asset paid by this batch; chains never share a batch.
    pub asset: Asset,
    /// Deployment network.
    pub network: ChainNetwork,
    /// Hash of the exact append-only ledger snapshot that authorized payment.
    pub ledger_root: [u8; 32],
    /// Reconciliation checkpoint proving collector funds were observed.
    pub reconciliation_id: Uuid,
    /// Exact ordered outputs.
    pub outputs: Vec<PayoutOutput>,
}

impl PayoutBatchRequest {
    /// Enforces bounded, nonzero, single-network signer input.
    pub fn validate(&self) -> Result<u64, SignerError> {
        if self.batch_id.is_nil()
            || self.reconciliation_id.is_nil()
            || self.ledger_root.iter().all(|byte| *byte == 0)
        {
            return Err(SignerError::InvalidRequest);
        }
        if self.outputs.is_empty() || self.outputs.len() > MAX_PAYOUT_OUTPUTS {
            return Err(SignerError::InvalidRequest);
        }
        let mut total = 0u64;
        let mut allocation_ids = HashSet::with_capacity(self.outputs.len());
        for output in &self.outputs {
            if output.allocation_id.is_nil()
                || !allocation_ids.insert(output.allocation_id)
                || output.amount_zat == 0
                || output.canonical_address.len() < 8
                || output.canonical_address.len() > 512
                || output.canonical_address.chars().any(char::is_whitespace)
            {
                return Err(SignerError::InvalidRequest);
            }
            total = total
                .checked_add(output.amount_zat)
                .ok_or(SignerError::InvalidRequest)?;
        }
        Ok(total)
    }

    /// Commits to every signer-relevant field for durable idempotency checks.
    pub fn commitment(&self) -> Result<[u8; 32], SignerError> {
        self.validate()?;
        let mut hasher = Sha256::new();
        hasher.update(PAYOUT_COMMITMENT_DOMAIN);
        hasher.update(self.batch_id.as_bytes());
        hasher.update([match self.asset {
            Asset::Wec => 1,
            Asset::Zec => 2,
        }]);
        hasher.update([match self.network {
            ChainNetwork::Testnet => 1,
            ChainNetwork::Mainnet => 2,
        }]);
        hasher.update(self.ledger_root);
        hasher.update(self.reconciliation_id.as_bytes());
        hasher.update(
            u16::try_from(self.outputs.len())
                .map_err(|_| SignerError::InvalidRequest)?
                .to_be_bytes(),
        );
        for output in &self.outputs {
            hasher.update(output.allocation_id.as_bytes());
            hasher.update([match output.receiver_kind {
                ReceiverKind::Transparent => 1,
                ReceiverKind::Ironwood => 2,
            }]);
            hasher.update(output.amount_zat.to_be_bytes());
            hasher.update(
                u16::try_from(output.canonical_address.len())
                    .map_err(|_| SignerError::InvalidRequest)?
                    .to_be_bytes(),
            );
            hasher.update(output.canonical_address.as_bytes());
        }
        Ok(hasher.finalize().into())
    }
}

/// Public receipt returned only after a signer resolved the broadcast outcome.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BroadcastReceipt {
    /// Stable payout batch identifier.
    pub batch_id: Uuid,
    /// Exact request commitment durably bound to the idempotency key.
    pub request_commitment: [u8; 32],
    /// Asset paid.
    pub asset: Asset,
    /// Chain transaction identifier in display byte order.
    pub transaction_id: String,
    /// Exact total output value.
    pub output_total_zat: u64,
}

/// Fail-closed isolated signer failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SignerError {
    /// Signer has deliberately not been configured.
    #[error("payout signer is not configured")]
    NotConfigured,
    /// Request violates a monetary or identity bound.
    #[error("payout request is invalid")]
    InvalidRequest,
    /// Request is not for the isolated Testnet deployment.
    #[error("payout signer rejected the network")]
    WrongNetwork,
    /// Same idempotency key was previously used with different content.
    #[error("payout batch conflicts with an earlier request")]
    IdempotencyConflict,
    /// Broadcast state is ambiguous and must be reconciled before retry.
    #[error("payout broadcast outcome requires reconciliation")]
    AmbiguousBroadcast,
    /// Wallet or node refused the exact transaction.
    #[error("payout transaction was rejected")]
    Rejected,
}

/// Spending-key service implemented outside the Internet-facing portal.
pub trait IsolatedPayoutSigner: Send + Sync {
    /// Confirms that the correctly fenced Testnet wallet and node are available.
    fn readiness(&self) -> Result<(), SignerError>;

    /// Signs and broadcasts an exact, idempotent Testnet batch.
    ///
    /// The signer must durably store `(batch_id, request commitment, txid)`
    /// before returning success. An exact retry returns the stored receipt; a
    /// different commitment with the same batch ID returns an idempotency
    /// conflict and never signs.
    fn sign_and_broadcast(
        &self,
        request: &PayoutBatchRequest,
    ) -> Result<BroadcastReceipt, SignerError>;
}

/// Explicit disabled signer used when wallet integration is absent.
#[derive(Debug, Default)]
pub struct DisabledPayoutSigner;

impl IsolatedPayoutSigner for DisabledPayoutSigner {
    fn readiness(&self) -> Result<(), SignerError> {
        Err(SignerError::NotConfigured)
    }

    fn sign_and_broadcast(
        &self,
        _request: &PayoutBatchRequest,
    ) -> Result<BroadcastReceipt, SignerError> {
        Err(SignerError::NotConfigured)
    }
}

/// Testnet-only orchestration guard around an isolated signer.
pub struct TestnetPayoutBoundary {
    signer: Arc<dyn IsolatedPayoutSigner>,
}

impl TestnetPayoutBoundary {
    /// Creates a boundary. Supplying a disabled signer is explicit and safe.
    pub fn new(signer: Arc<dyn IsolatedPayoutSigner>) -> Self {
        Self { signer }
    }

    /// Checks the isolated signer without constructing or signing a payment.
    pub fn readiness(&self) -> Result<(), SignerError> {
        self.signer.readiness()
    }

    /// Validates and delegates an exact Testnet request.
    pub fn execute(&self, request: &PayoutBatchRequest) -> Result<BroadcastReceipt, SignerError> {
        if request.network != ChainNetwork::Testnet {
            return Err(SignerError::WrongNetwork);
        }
        let expected_total = request.validate()?;
        let expected_commitment = request.commitment()?;
        let receipt = self.signer.sign_and_broadcast(request)?;
        if receipt.batch_id != request.batch_id
            || receipt.request_commitment != expected_commitment
            || receipt.asset != request.asset
            || receipt.output_total_zat != expected_total
            || receipt.transaction_id.len() != 64
            || !receipt
                .transaction_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(SignerError::Rejected);
        }
        Ok(receipt)
    }
}

impl fmt::Debug for TestnetPayoutBoundary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TestnetPayoutBoundary")
            .field("signer", &"[ISOLATED]")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    struct FixedSigner;

    impl IsolatedPayoutSigner for FixedSigner {
        fn readiness(&self) -> Result<(), SignerError> {
            Ok(())
        }

        fn sign_and_broadcast(
            &self,
            request: &PayoutBatchRequest,
        ) -> Result<BroadcastReceipt, SignerError> {
            Ok(BroadcastReceipt {
                batch_id: request.batch_id,
                request_commitment: request.commitment()?,
                asset: request.asset,
                transaction_id: "a".repeat(64),
                output_total_zat: request.outputs.iter().map(|output| output.amount_zat).sum(),
            })
        }
    }

    fn request(network: ChainNetwork) -> PayoutBatchRequest {
        PayoutBatchRequest {
            batch_id: Uuid::from_u128(1),
            asset: Asset::Wec,
            network,
            ledger_root: [1; 32],
            reconciliation_id: Uuid::from_u128(2),
            outputs: vec![PayoutOutput {
                allocation_id: Uuid::from_u128(3),
                canonical_address: "wcash-test-address-value".to_owned(),
                receiver_kind: ReceiverKind::Ironwood,
                amount_zat: 5,
            }],
        }
    }

    #[test]
    fn disabled_signer_fails_closed() {
        let boundary = TestnetPayoutBoundary::new(Arc::new(DisabledPayoutSigner));
        assert_eq!(
            boundary.execute(&request(ChainNetwork::Testnet)),
            Err(SignerError::NotConfigured)
        );
    }

    #[test]
    fn mainnet_can_never_cross_testnet_boundary() {
        let boundary = TestnetPayoutBoundary::new(Arc::new(FixedSigner));
        assert_eq!(
            boundary.execute(&request(ChainNetwork::Mainnet)),
            Err(SignerError::WrongNetwork)
        );
    }

    #[test]
    fn exact_receipt_is_accepted() {
        let boundary = TestnetPayoutBoundary::new(Arc::new(FixedSigner));
        let receipt = boundary
            .execute(&request(ChainNetwork::Testnet))
            .unwrap_or_else(|error| panic!("unexpected signer failure: {error}"));
        assert_eq!(receipt.output_total_zat, 5);
    }

    #[test]
    fn request_rejects_zero_and_overflow() {
        let mut invalid = request(ChainNetwork::Testnet);
        invalid.outputs[0].amount_zat = 0;
        assert_eq!(invalid.validate(), Err(SignerError::InvalidRequest));
        invalid.outputs = vec![
            PayoutOutput {
                allocation_id: Uuid::from_u128(4),
                canonical_address: "wcash-test-address-one".to_owned(),
                receiver_kind: ReceiverKind::Ironwood,
                amount_zat: u64::MAX,
            },
            PayoutOutput {
                allocation_id: Uuid::from_u128(5),
                canonical_address: "wcash-test-address-two".to_owned(),
                receiver_kind: ReceiverKind::Ironwood,
                amount_zat: 1,
            },
        ];
        assert_eq!(invalid.validate(), Err(SignerError::InvalidRequest));
    }

    #[test]
    fn commitment_changes_with_every_monetary_field() {
        let original = request(ChainNetwork::Testnet);
        let original_commitment = original
            .commitment()
            .unwrap_or_else(|error| panic!("unexpected commitment failure: {error}"));
        let mut changed = original.clone();
        changed.outputs[0].amount_zat += 1;
        assert_ne!(
            original_commitment,
            changed
                .commitment()
                .unwrap_or_else(|error| panic!("unexpected commitment failure: {error}"))
        );
        changed = original.clone();
        changed.outputs[0].canonical_address.push('x');
        assert_ne!(
            original_commitment,
            changed
                .commitment()
                .unwrap_or_else(|error| panic!("unexpected commitment failure: {error}"))
        );
    }

    #[test]
    fn duplicate_allocation_cannot_be_paid_twice() {
        let mut duplicate = request(ChainNetwork::Testnet);
        duplicate.outputs.push(duplicate.outputs[0].clone());
        assert_eq!(duplicate.validate(), Err(SignerError::InvalidRequest));
        assert_eq!(duplicate.commitment(), Err(SignerError::InvalidRequest));
    }
}
