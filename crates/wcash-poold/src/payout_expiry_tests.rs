#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::*;
use std::{collections::VecDeque, sync::Mutex as StdMutex};
use wcash_pool_portal::{
    Asset, BroadcastReceipt, ChainNetwork, PayoutBatchRequest, PayoutOutput, ReceiverKind,
};
use wcash_pool_store::SignedPayoutArtifact;

const EXPIRY: u32 = 240;

fn candidate(id: u128, held: bool) -> PayoutExpiryCandidate {
    let batch_id = Uuid::from_u128(id);
    let mut c = PayoutExpiryCandidate {
        artifact: SignedPayoutArtifact {
            batch_id,
            chain: Chain::Wcash,
            state: if held {
                PayoutBatchState::ExpiryPending
            } else {
                PayoutBatchState::Broadcast
            },
            unsigned_digest: [31; 32],
            transaction_id: [id as u8; 32],
            signed_transaction: vec![6, 0, 0, 128, id as u8],
            network_fee_zat: 100,
        },
        request: PayoutBatchRequest {
            batch_id,
            asset: Asset::Wec,
            network: ChainNetwork::Testnet,
            ledger_root: [42; 32],
            reconciliation_id: Uuid::from_u128(10_000 + id),
            maximum_network_fee_zat: 1_000,
            outputs: vec![PayoutOutput {
                allocation_id: Uuid::from_u128(20_000 + id),
                canonical_address: "wtestsapling1recipient".to_owned(),
                receiver_kind: ReceiverKind::Ironwood,
                amount_zat: 754_270_863,
            }],
        },
        reconciliation_tip_height: 200,
        quarantine: None,
    };
    if held {
        c.quarantine = Some(evidence(&c, EXPIRY + 1));
    }
    c
}

fn evidence(c: &PayoutExpiryCandidate, height: u32) -> PayoutExpiryEvidence {
    PayoutExpiryEvidence {
        transaction_id: c.artifact.transaction_id,
        signed_transaction_sha256: Sha256::digest(&c.artifact.signed_transaction).into(),
        expiry_height: EXPIRY,
        tip_hash: [99; 32],
        tip_height: height,
        observed_at: 1_000,
    }
}

fn prepared(c: &PayoutExpiryCandidate) -> WecPreparedPayout {
    WecPreparedPayout {
        receipt: BroadcastReceipt {
            batch_id: c.artifact.batch_id,
            request_commitment: c.request.commitment().unwrap(),
            asset: Asset::Wec,
            transaction_id: hex::encode(c.artifact.transaction_id),
            output_total_zat: c.request.outputs[0].amount_zat,
        },
        unsigned_digest: c.artifact.unsigned_digest,
        transaction_id_bytes: c.artifact.transaction_id,
        signed_transaction: c.artifact.signed_transaction.clone(),
        network_fee_zat: c.artifact.network_fee_zat,
        target_height: EXPIRY - 40,
        expiry_height: EXPIRY,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Transition {
    Hold(Uuid, PayoutExpiryEvidence),
    Expire(Uuid, PayoutExpiryEvidence),
    Confirm(Uuid, PayoutConfirmation),
}

#[derive(Default)]
struct Store {
    candidates: StdMutex<Vec<PayoutExpiryCandidate>>,
    transitions: StdMutex<Vec<Transition>>,
    confirmations_succeed: StdMutex<bool>,
}
impl Store {
    fn replace(&self, c: Vec<PayoutExpiryCandidate>) {
        *self.candidates.lock().unwrap() = c;
    }
    fn transitions(&self) -> Vec<Transition> {
        self.transitions.lock().unwrap().clone()
    }
}
impl ExpiryStore for Store {
    fn candidates(&self) -> RecoveryFuture<'_, Vec<PayoutExpiryCandidate>> {
        let c = self.candidates.lock().unwrap().clone();
        Box::pin(async move { Ok(c) })
    }
    fn hold(&self, id: Uuid, e: PayoutExpiryEvidence) -> RecoveryFuture<'_, ()> {
        self.transitions
            .lock()
            .unwrap()
            .push(Transition::Hold(id, e));
        Box::pin(async { Ok(()) })
    }
    fn expire(&self, id: Uuid, e: PayoutExpiryEvidence) -> RecoveryFuture<'_, ()> {
        self.transitions
            .lock()
            .unwrap()
            .push(Transition::Expire(id, e));
        Box::pin(async { Ok(()) })
    }
    fn confirm(&self, id: Uuid, e: PayoutConfirmation) -> RecoveryFuture<'_, bool> {
        self.transitions
            .lock()
            .unwrap()
            .push(Transition::Confirm(id, e));
        let result = *self.confirmations_succeed.lock().unwrap();
        Box::pin(async move { Ok(result) })
    }
}
#[derive(Default)]
struct Inspector {
    calls: StdMutex<Vec<Uuid>>,
    results: StdMutex<VecDeque<Result<WecPreparedPayout, PayoutRuntimeError>>>,
}
impl ExpiryInspector for Inspector {
    fn inspect(&self, c: PayoutExpiryCandidate) -> RecoveryFuture<'_, WecPreparedPayout> {
        self.calls.lock().unwrap().push(c.artifact.batch_id);
        let result = self
            .results
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Ok(prepared(&c)));
        Box::pin(async move { result })
    }
}
#[derive(Default)]
struct Authority {
    calls: StdMutex<Vec<Vec<ExpiryWatch>>>,
    results: StdMutex<VecDeque<Result<Vec<ExpiryObservation>, ObservationFailure>>>,
}
impl ExpiryAuthority for Authority {
    fn expiry_snapshot(
        &self,
        w: Vec<ExpiryWatch>,
    ) -> ObservationFuture<'_, Vec<ExpiryObservation>> {
        self.calls.lock().unwrap().push(w);
        let result = self
            .results
            .lock()
            .unwrap()
            .pop_front()
            .expect("scripted authority result");
        Box::pin(async move { result })
    }
}
struct Fixture {
    store: Arc<Store>,
    inspector: Arc<Inspector>,
    authority: Arc<Authority>,
    recovery: WecPayoutExpiryRecovery,
}
impl Fixture {
    fn new(c: Vec<PayoutExpiryCandidate>) -> Self {
        let store = Arc::new(Store::default());
        store.replace(c);
        let inspector = Arc::new(Inspector::default());
        let authority = Arc::new(Authority::default());
        let recovery =
            WecPayoutExpiryRecovery::new(store.clone(), inspector.clone(), authority.clone());
        Self {
            store,
            inspector,
            authority,
            recovery,
        }
    }
    fn observe(&self, id: Uuid, state: ExpiryChainState) {
        self.authority
            .results
            .lock()
            .unwrap()
            .push_back(Ok(vec![ExpiryObservation {
                batch_id: id,
                state,
            }]));
    }
}

#[tokio::test]
async fn empty_recovery_does_not_inspect_or_contact_authority() {
    let f = Fixture::new(vec![]);
    assert!(f.recovery.recover().await.unwrap());
    assert!(f.inspector.calls.lock().unwrap().is_empty());
    assert!(f.authority.calls.lock().unwrap().is_empty());
    assert!(f.store.transitions().is_empty());
}
#[tokio::test]
async fn inspection_is_separate_pass_without_chain_or_settlement_effects() {
    let c = candidate(1, false);
    let f = Fixture::new(vec![c.clone()]);
    assert!(!f.recovery.recover().await.unwrap());
    assert_eq!(*f.inspector.calls.lock().unwrap(), [c.artifact.batch_id]);
    assert!(f.authority.calls.lock().unwrap().is_empty());
    assert!(f.store.transitions().is_empty());
    f.observe(c.artifact.batch_id, ExpiryChainState::Unexpired);
    assert!(f.recovery.recover().await.unwrap());
    assert_eq!(f.inspector.calls.lock().unwrap().len(), 1);
    assert!(f.store.transitions().is_empty());
}
#[tokio::test]
async fn missing_expired_batch_holds_reserve_without_releasing_before_finality() {
    let c = candidate(1, false);
    let f = Fixture::new(vec![c.clone()]);
    assert!(!f.recovery.recover().await.unwrap());
    let first = evidence(&c, EXPIRY + 1);
    f.observe(
        c.artifact.batch_id,
        ExpiryChainState::Missing(first.clone()),
    );
    assert!(!f.recovery.recover().await.unwrap());
    assert_eq!(
        f.store.transitions(),
        [Transition::Hold(c.artifact.batch_id, first)]
    );
    let held = candidate(1, true);
    f.store.replace(vec![held.clone()]);
    f.observe(
        held.artifact.batch_id,
        ExpiryChainState::Missing(evidence(&held, EXPIRY + 1_000)),
    );
    assert!(f.recovery.recover().await.unwrap());
    assert_eq!(f.store.transitions().len(), 1);
}
#[tokio::test]
async fn held_release_requires_final_missing_and_removes_row_before_replay() {
    let c = candidate(1, true);
    let f = Fixture::new(vec![c.clone()]);
    assert!(!f.recovery.recover().await.unwrap());
    let e = evidence(&c, EXPIRY + WCASH_EXPIRY_FINALITY_DEPTH);
    f.observe(
        c.artifact.batch_id,
        ExpiryChainState::FinalMissing(e.clone()),
    );
    assert!(!f.recovery.recover().await.unwrap());
    assert_eq!(
        f.store.transitions(),
        [Transition::Expire(c.artifact.batch_id, e)]
    );
    f.store.replace(vec![]);
    assert!(f.recovery.recover().await.unwrap());
    assert_eq!(f.store.transitions().len(), 1);
}
#[tokio::test]
async fn held_original_mined_confirms_original_reserve_and_defers_new_signing() {
    let c = candidate(1, true);
    let f = Fixture::new(vec![c.clone()]);
    *f.store.confirmations_succeed.lock().unwrap() = true;
    assert!(!f.recovery.recover().await.unwrap());
    let conf = PayoutConfirmation {
        block_hash: [71; 32],
        block_height: EXPIRY - 1,
        confirmations: 2,
    };
    f.observe(c.artifact.batch_id, ExpiryChainState::Mined(conf.clone()));
    assert!(!f.recovery.recover().await.unwrap());
    assert_eq!(
        f.store.transitions(),
        [Transition::Confirm(c.artifact.batch_id, conf)]
    );
}
#[tokio::test]
async fn held_mempool_reorg_or_premature_confirmation_never_allows_fresh_settlement() {
    let c = candidate(1, true);
    let f = Fixture::new(vec![c.clone()]);
    assert!(!f.recovery.recover().await.unwrap());
    f.observe(c.artifact.batch_id, ExpiryChainState::Unresolved);
    assert!(!f.recovery.recover().await.unwrap());
    assert!(f.store.transitions().is_empty());
    f.observe(
        c.artifact.batch_id,
        ExpiryChainState::Mined(PayoutConfirmation {
            block_hash: [71; 32],
            block_height: EXPIRY - 1,
            confirmations: 1,
        }),
    );
    assert!(!f.recovery.recover().await.unwrap());
    assert!(!f
        .store
        .transitions()
        .iter()
        .any(|x| matches!(x, Transition::Expire(..))));
}
#[tokio::test]
async fn premature_final_missing_or_misbound_evidence_never_releases() {
    for change in 0..4 {
        let c = candidate(1, true);
        let f = Fixture::new(vec![c.clone()]);
        assert!(!f.recovery.recover().await.unwrap());
        let mut e = evidence(&c, EXPIRY + WCASH_EXPIRY_FINALITY_DEPTH);
        match change {
            0 => e.tip_height -= 1,
            1 => e.transaction_id = [2; 32],
            2 => e.signed_transaction_sha256 = [3; 32],
            _ => e.expiry_height -= 1,
        }
        f.observe(c.artifact.batch_id, ExpiryChainState::FinalMissing(e));
        assert!(f.recovery.recover().await.is_err());
        assert!(f.store.transitions().is_empty());
    }
}
#[tokio::test]
async fn native_inspection_mismatched_artifacts_fail_closed() {
    for change in 0..6 {
        let c = candidate(1, false);
        let f = Fixture::new(vec![c.clone()]);
        let mut p = prepared(&c);
        match change {
            0 => p.signed_transaction.push(9),
            1 => p.transaction_id_bytes = [9; 32],
            2 => p.receipt.request_commitment = [9; 32],
            3 => p.expiry_height = 0,
            4 => p.expiry_height = p.target_height + 101,
            _ => p.unsigned_digest = [9; 32],
        }
        f.inspector.results.lock().unwrap().push_back(Ok(p));
        assert!(f.recovery.recover().await.is_err());
        assert!(f.authority.calls.lock().unwrap().is_empty());
        assert!(f.store.transitions().is_empty());
    }
}
#[tokio::test]
async fn changed_signed_bytes_cannot_reuse_previous_native_inspection() {
    let mut c = candidate(1, true);
    let f = Fixture::new(vec![c.clone()]);
    assert!(!f.recovery.recover().await.unwrap());
    c.artifact.signed_transaction.push(99);
    f.store.replace(vec![c]);
    assert!(f.recovery.recover().await.is_err());
    assert_eq!(f.inspector.calls.lock().unwrap().len(), 1);
    assert!(f.authority.calls.lock().unwrap().is_empty());
    assert!(f.store.transitions().is_empty());
}
#[tokio::test]
async fn oversized_or_duplicate_candidates_are_not_partially_observed() {
    let f = Fixture::new(vec![
        candidate(1, true),
        candidate(2, true),
        candidate(3, true),
    ]);
    assert!(f.recovery.recover().await.is_err());
    assert!(f.inspector.calls.lock().unwrap().is_empty());
    assert!(f.authority.calls.lock().unwrap().is_empty());
    let c = candidate(1, true);
    f.store.replace(vec![c.clone(), c]);
    assert!(f.recovery.recover().await.is_err());
    assert!(f.authority.calls.lock().unwrap().is_empty());
    assert!(f.store.transitions().is_empty());
}
#[tokio::test]
async fn duplicate_observations_cannot_partially_hold_or_release() {
    let c = candidate(1, false);
    let f = Fixture::new(vec![c.clone(), candidate(2, false)]);
    assert!(!f.recovery.recover().await.unwrap());
    let o = ExpiryObservation {
        batch_id: c.artifact.batch_id,
        state: ExpiryChainState::Missing(evidence(&c, EXPIRY + 1)),
    };
    f.authority
        .results
        .lock()
        .unwrap()
        .push_back(Ok(vec![o.clone(), o]));
    assert!(f.recovery.recover().await.is_err());
    assert!(
        f.store.transitions().is_empty(),
        "validate entire result set before accounting effects"
    );
}
#[tokio::test]
async fn authority_transport_failure_never_changes_a_reservation() {
    let f = Fixture::new(vec![candidate(1, true)]);
    assert!(!f.recovery.recover().await.unwrap());
    f.authority
        .results
        .lock()
        .unwrap()
        .push_back(Err(ObservationFailure::Unavailable));
    assert!(matches!(
        f.recovery.recover().await,
        Err(PayoutRuntimeError::AuthorityUnavailable { .. })
    ));
    assert!(f.store.transitions().is_empty());
}
