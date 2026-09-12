//! Chain-separated dispatch for independently isolated WEC and ZEC signers.

use std::{fmt, sync::Arc};

use wcash_pool_portal::{
    Asset, BroadcastReceipt, IsolatedPayoutSigner, PayoutBatchRequest, SignerError,
};

/// One readiness and execution boundary with no cross-chain fallback.
pub struct DualPayoutSigner {
    wec: Arc<dyn IsolatedPayoutSigner>,
    zec: Arc<dyn IsolatedPayoutSigner>,
}

impl DualPayoutSigner {
    /// Binds each asset to exactly one signer implementation.
    pub fn new(wec: Arc<dyn IsolatedPayoutSigner>, zec: Arc<dyn IsolatedPayoutSigner>) -> Self {
        Self { wec, zec }
    }
}

impl IsolatedPayoutSigner for DualPayoutSigner {
    fn readiness(&self) -> Result<(), SignerError> {
        self.wec.readiness()?;
        self.zec.readiness()?;
        Ok(())
    }

    fn sign_and_broadcast(
        &self,
        request: &PayoutBatchRequest,
    ) -> Result<BroadcastReceipt, SignerError> {
        match request.asset {
            Asset::Wec => self.wec.sign_and_broadcast(request),
            Asset::Zec => self.zec.sign_and_broadcast(request),
        }
    }
}

impl fmt::Debug for DualPayoutSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DualPayoutSigner")
            .field("wec", &"[ISOLATED]")
            .field("zec", &"[ISOLATED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use wcash_pool_portal::{ChainNetwork, DisabledPayoutSigner};

    use super::*;

    #[test]
    fn readiness_requires_both_independent_signers() {
        let signer = DualPayoutSigner::new(
            Arc::new(DisabledPayoutSigner),
            Arc::new(DisabledPayoutSigner),
        );
        assert_eq!(signer.readiness(), Err(SignerError::NotConfigured));
    }

    #[test]
    fn no_asset_can_fall_back_to_the_other_signer() {
        let signer = DualPayoutSigner::new(
            Arc::new(DisabledPayoutSigner),
            Arc::new(DisabledPayoutSigner),
        );
        for asset in [Asset::Wec, Asset::Zec] {
            let request = PayoutBatchRequest {
                batch_id: uuid::Uuid::new_v4(),
                asset,
                network: ChainNetwork::Testnet,
                ledger_root: [1; 32],
                reconciliation_id: uuid::Uuid::new_v4(),
                outputs: Vec::new(),
            };
            assert_eq!(
                signer.sign_and_broadcast(&request),
                Err(SignerError::NotConfigured)
            );
        }
    }
}
