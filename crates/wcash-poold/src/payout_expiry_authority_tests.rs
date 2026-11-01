#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::*;
use std::{collections::VecDeque, sync::Mutex};
use wcash_pool_portal::{Asset, PayoutBatchRequest, PayoutOutput, ReceiverKind};
use wcash_pool_store::PayoutExpiryCandidate;

const EXPIRY: u32 = 240;
const GENESIS: [u8; 32] = [1; 32];
const TIP: [u8; 32] = [2; 32];
const CHECKPOINT: [u8; 32] = [3; 32];
const TX: [u8; 32] = [4; 32];

struct Step {
    method: &'static str,
    params: Value,
    result: Result<Value, RpcFailure>,
}
struct Rpc {
    steps: Mutex<VecDeque<Step>>,
}
impl Rpc {
    fn new(steps: Vec<Step>) -> Arc<Self> {
        Arc::new(Self {
            steps: Mutex::new(steps.into()),
        })
    }
    fn drained(&self) {
        assert!(self.steps.lock().unwrap().is_empty());
    }
}
impl BoundedRpcClient for Rpc {
    fn call(&self, method: &'static str, params: Value, limits: RpcLimits) -> RpcFuture<'_> {
        assert!(!limits.timeout.is_zero());
        assert!(limits.maximum_response_bytes > 0);
        let step = self
            .steps
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| panic!("unexpected RPC: {method}"));
        assert_eq!(step.method, method);
        assert_eq!(step.params, params);
        Box::pin(async move { step.result })
    }
}
fn ok(method: &'static str, params: Value, result: Value) -> Step {
    Step {
        method,
        params,
        result: Ok(result),
    }
}
fn missing() -> Step {
    Step {
        method: "getrawtransaction",
        params: json!([hex::encode(TX), 1]),
        result: Err(RpcFailure::Server(-5)),
    }
}
fn display(mut hash: [u8; 32]) -> String {
    hash.reverse();
    hex::encode(hash)
}
fn tip(steps: &mut Vec<Step>, height: u32, hash: [u8; 32]) {
    let branch = expected_branch(Chain::Wcash);
    steps.extend([
        ok("getblockchaininfo",json!([]),json!({"chain":"test","blocks":height,"headers":height,"bestblockhash":display(hash),"consensus":{"chaintip":branch,"nextblock":branch}})),
        ok("getblockhash",json!([0]),json!(display(GENESIS))),
        ok("getbestblockheightandhash",json!([]),json!({"height":height,"hash":hash})),
    ]);
}
fn watch(held: bool) -> ExpiryWatch {
    let id = Uuid::from_u128(1);
    let artifact = SignedPayoutArtifact {
        batch_id: id,
        chain: Chain::Wcash,
        state: if held {
            PayoutBatchState::ExpiryPending
        } else {
            PayoutBatchState::Broadcast
        },
        unsigned_digest: [6; 32],
        transaction_id: TX,
        signed_transaction: vec![6, 0, 0, 128, 77],
        network_fee_zat: 100,
    };
    let request = PayoutBatchRequest {
        batch_id: id,
        asset: Asset::Wec,
        network: ChainNetwork::Testnet,
        ledger_root: [7; 32],
        reconciliation_id: Uuid::from_u128(8),
        maximum_network_fee_zat: 1000,
        outputs: vec![PayoutOutput {
            allocation_id: Uuid::from_u128(9),
            canonical_address: "wtestsapling1recipient".to_owned(),
            receiver_kind: ReceiverKind::Ironwood,
            amount_zat: 5000,
        }],
    };
    let quarantine = held.then(|| PayoutExpiryEvidence {
        transaction_id: TX,
        signed_transaction_sha256: Sha256::digest(&artifact.signed_transaction).into(),
        expiry_height: EXPIRY,
        tip_hash: TIP,
        tip_height: EXPIRY + 1,
        observed_at: 1,
    });
    ExpiryWatch {
        candidate: PayoutExpiryCandidate {
            artifact,
            request,
            reconciliation_tip_height: 200,
            quarantine,
        },
        expiry_height: EXPIRY,
    }
}
fn authority(rpc: Arc<Rpc>) -> NodePayoutAuthority {
    NodePayoutAuthority::with_client(Chain::Wcash, rpc, GENESIS).unwrap()
}

#[tokio::test]
async fn active_at_expiry_boundary_does_not_query_or_quarantine_transaction() {
    let mut steps = vec![];
    tip(&mut steps, EXPIRY, TIP);
    tip(&mut steps, EXPIRY, TIP);
    let rpc = Rpc::new(steps);
    let result = authority(rpc.clone())
        .expiry_snapshot(vec![watch(false)])
        .await
        .unwrap();
    assert_eq!(result[0].state, ExpiryChainState::Unexpired);
    rpc.drained();
}

#[tokio::test]
async fn held_rollback_to_expiry_remains_unresolved_and_never_releases() {
    let mut steps = vec![];
    tip(&mut steps, EXPIRY, TIP);
    steps.push(missing());
    tip(&mut steps, EXPIRY, TIP);
    let rpc = Rpc::new(steps);
    let result = authority(rpc.clone())
        .expiry_snapshot(vec![watch(true)])
        .await
        .unwrap();
    assert_eq!(result[0].state, ExpiryChainState::Unresolved);
    rpc.drained();
}

#[tokio::test]
async fn thousand_blocks_after_expiry_is_still_not_final_missing() {
    let height = EXPIRY + 1_000;
    let mut steps = vec![];
    tip(&mut steps, height, TIP);
    steps.push(missing());
    tip(&mut steps, height, TIP);
    let rpc = Rpc::new(steps);
    let result = authority(rpc.clone())
        .expiry_snapshot(vec![watch(true)])
        .await
        .unwrap();
    assert!(matches!(result[0].state, ExpiryChainState::Missing(_)));
    rpc.drained();
}

fn final_steps() -> Vec<Step> {
    let height = EXPIRY + WCASH_EXPIRY_FINALITY_DEPTH;
    let mut steps = vec![];
    tip(&mut steps, height, TIP);
    steps.push(missing());
    steps.push(ok("getrawmempool", json!([]), json!([])));
    steps.push(ok(
        "getblockhash",
        json!([EXPIRY]),
        json!(display(CHECKPOINT)),
    ));
    tip(&mut steps, height, TIP);
    steps.push(ok(
        "getblockhash",
        json!([EXPIRY]),
        json!(display(CHECKPOINT)),
    ));
    steps
}

#[tokio::test]
async fn finalized_noninclusion_requires_index_mempool_and_stable_checkpoint() {
    let rpc = Rpc::new(final_steps());
    let w = watch(true);
    let result = authority(rpc.clone())
        .expiry_snapshot(vec![w.clone()])
        .await
        .unwrap();
    let ExpiryChainState::FinalMissing(e) = &result[0].state else {
        panic!("expected finalized absence")
    };
    assert_eq!(e.transaction_id, TX);
    assert_eq!(e.expiry_height, EXPIRY);
    assert_eq!(e.tip_height, EXPIRY + WCASH_EXPIRY_FINALITY_DEPTH);
    assert_eq!(
        e.signed_transaction_sha256,
        <[u8; 32]>::from(Sha256::digest(&w.candidate.artifact.signed_transaction))
    );
    rpc.drained();
}

#[tokio::test]
async fn finalized_lookup_missing_but_mempool_present_is_not_absence() {
    let height = EXPIRY + WCASH_EXPIRY_FINALITY_DEPTH;
    let mut steps = vec![];
    tip(&mut steps, height, TIP);
    steps.push(missing());
    steps.push(ok("getrawmempool", json!([]), json!([hex::encode(TX)])));
    let rpc = Rpc::new(steps);
    assert_eq!(
        authority(rpc.clone())
            .expiry_snapshot(vec![watch(true)])
            .await,
        Err(ObservationFailure::Unavailable)
    );
    rpc.drained();
}

#[tokio::test]
async fn changed_finalized_checkpoint_invalidates_entire_snapshot() {
    let mut steps = final_steps();
    steps.last_mut().unwrap().result = Ok(json!(display([91; 32])));
    let rpc = Rpc::new(steps);
    assert_eq!(
        authority(rpc.clone())
            .expiry_snapshot(vec![watch(true)])
            .await,
        Err(ObservationFailure::Unavailable)
    );
    rpc.drained();
}

#[tokio::test]
async fn moved_tip_invalidates_noninclusion_before_release() {
    let height = EXPIRY + 1;
    let mut steps = vec![];
    tip(&mut steps, height, TIP);
    steps.push(missing());
    tip(&mut steps, height + 1, [92; 32]);
    let rpc = Rpc::new(steps);
    assert_eq!(
        authority(rpc.clone())
            .expiry_snapshot(vec![watch(true)])
            .await,
        Err(ObservationFailure::Unavailable)
    );
    rpc.drained();
}

#[tokio::test]
async fn existing_transaction_must_match_every_signed_byte() {
    let mut steps = vec![];
    tip(&mut steps, EXPIRY + 1, TIP);
    steps.push(ok(
        "getrawtransaction",
        json!([hex::encode(TX), 1]),
        json!({"hex":"060000804e","txid":hex::encode(TX),"confirmations":0}),
    ));
    let rpc = Rpc::new(steps);
    assert_eq!(
        authority(rpc.clone())
            .expiry_snapshot(vec![watch(true)])
            .await,
        Err(ObservationFailure::Invariant)
    );
    rpc.drained();
}

#[tokio::test]
async fn exact_canonical_original_can_confirm_after_expiry() {
    let w = watch(true);
    let block_height = EXPIRY - 1;
    let height = EXPIRY + 1;
    let mut steps = vec![];
    tip(&mut steps, height, TIP);
    steps.push(ok("getrawtransaction",json!([hex::encode(TX),1]),json!({"hex":hex::encode(&w.candidate.artifact.signed_transaction),"txid":hex::encode(TX),"height":block_height,"blockhash":display(CHECKPOINT),"confirmations":3})));
    steps.push(ok(
        "getblockhash",
        json!([block_height]),
        json!(display(CHECKPOINT)),
    ));
    tip(&mut steps, height, TIP);
    let rpc = Rpc::new(steps);
    let result = authority(rpc.clone())
        .expiry_snapshot(vec![w])
        .await
        .unwrap();
    assert_eq!(
        result[0].state,
        ExpiryChainState::Mined(PayoutConfirmation {
            block_hash: CHECKPOINT,
            block_height,
            confirmations: 3
        })
    );
    rpc.drained();
}

#[tokio::test]
async fn malformed_mempool_or_expiry_overflow_cannot_release() {
    let height = EXPIRY + WCASH_EXPIRY_FINALITY_DEPTH;
    let mut steps = vec![];
    tip(&mut steps, height, TIP);
    steps.push(missing());
    steps.push(ok("getrawmempool", json!([]), json!(["invalid"])));
    let rpc = Rpc::new(steps);
    assert_eq!(
        authority(rpc.clone())
            .expiry_snapshot(vec![watch(true)])
            .await,
        Err(ObservationFailure::Invariant)
    );
    rpc.drained();
    // Checked addition must never wrap a near-maximum expiry into apparent finality.
    let mut w = watch(true);
    w.expiry_height = u32::MAX - 1;
    let mut steps = vec![];
    tip(&mut steps, u32::MAX, TIP);
    steps.push(missing());
    tip(&mut steps, u32::MAX, TIP);
    let rpc = Rpc::new(steps);
    let result = authority(rpc.clone())
        .expiry_snapshot(vec![w])
        .await
        .unwrap();
    assert!(matches!(result[0].state, ExpiryChainState::Missing(_)));
    rpc.drained();
}

fn exact_orphan(w: &ExpiryWatch) -> Value {
    json!({
        "hex": hex::encode(&w.candidate.artifact.signed_transaction),
        "txid": hex::encode(w.candidate.artifact.transaction_id),
        "in_active_chain": false,
        "height": -1,
        "blockhash": display(CHECKPOINT),
        "confirmations": 0,
        "expiryheight": EXPIRY,
    })
}

fn orphan_lookup_steps(w: &ExpiryWatch, height: u32) -> Vec<Step> {
    let mut steps = vec![];
    tip(&mut steps, height, TIP);
    steps.push(ok(
        "getrawtransaction",
        json!([hex::encode(TX), 1]),
        exact_orphan(w),
    ));
    steps
}

#[tokio::test]
async fn exact_expired_orphan_and_explicit_mempool_absence_only_authorize_hold() {
    for held in [false, true] {
        let w = watch(held);
        let mut steps = orphan_lookup_steps(&w, EXPIRY + 1);
        steps.push(ok("getrawmempool", json!([]), json!([])));
        tip(&mut steps, EXPIRY + 1, TIP);
        let rpc = Rpc::new(steps);
        let result = authority(rpc.clone())
            .expiry_snapshot(vec![w.clone()])
            .await
            .unwrap();
        let ExpiryChainState::ExpiredOrphan(e) = &result[0].state else {
            panic!("known orphan must authorize hold only")
        };
        assert_eq!(e.transaction_id, TX);
        assert_eq!(e.expiry_height, EXPIRY);
        assert_eq!(e.tip_height, EXPIRY + 1);
        assert_eq!(e.tip_hash, TIP);
        assert_ne!(e.observed_at, 0);
        assert_eq!(
            e.signed_transaction_sha256,
            <[u8; 32]>::from(Sha256::digest(&w.candidate.artifact.signed_transaction))
        );
        rpc.drained();
    }
}

#[tokio::test]
async fn known_orphan_beyond_finality_is_not_authoritative_transaction_absence() {
    let w = watch(true);
    let height = EXPIRY + 2 * WCASH_EXPIRY_FINALITY_DEPTH;
    let mut steps = orphan_lookup_steps(&w, height);
    steps.push(ok("getrawmempool", json!([]), json!([])));
    tip(&mut steps, height, TIP);
    let rpc = Rpc::new(steps);
    let result = authority(rpc.clone())
        .expiry_snapshot(vec![w])
        .await
        .unwrap();
    assert!(matches!(
        result[0].state,
        ExpiryChainState::ExpiredOrphan(_)
    ));
    // No finalized-absence checkpoint RPC is permitted for a positive lookup.
    rpc.drained();
}

#[tokio::test]
async fn known_orphan_reappearing_in_mempool_remains_unresolved() {
    for held in [false, true] {
        let w = watch(held);
        let mut steps = orphan_lookup_steps(&w, EXPIRY + 1);
        steps.push(ok(
            "getrawmempool",
            json!([]),
            json!([hex::encode([8; 32]), hex::encode(TX), hex::encode([9; 32])]),
        ));
        tip(&mut steps, EXPIRY + 1, TIP);
        let rpc = Rpc::new(steps);
        let result = authority(rpc.clone())
            .expiry_snapshot(vec![w])
            .await
            .unwrap();
        assert_eq!(result[0].state, ExpiryChainState::Unresolved);
        rpc.drained();
    }
}

#[tokio::test]
async fn known_orphan_requires_every_mempool_id_to_be_canonical() {
    for mempool in [
        json!(null),
        json!({}),
        json!(["invalid"]),
        json!([hex::encode(TX), "invalid"]),
        json!([hex::encode([8; 32]), hex::encode([0xab; 32]).to_uppercase()]),
    ] {
        let w = watch(true);
        let mut steps = orphan_lookup_steps(&w, EXPIRY + 1);
        steps.push(ok("getrawmempool", json!([]), mempool));
        let rpc = Rpc::new(steps);
        assert_eq!(
            authority(rpc.clone()).expiry_snapshot(vec![w]).await,
            Err(ObservationFailure::Invariant)
        );
        rpc.drained();
    }
}

#[tokio::test]
async fn known_orphan_mempool_rpc_failure_cannot_authorize_hold() {
    for failure in [
        RpcFailure::Timeout,
        RpcFailure::Unavailable,
        RpcFailure::Server(-28),
    ] {
        let w = watch(true);
        let mut steps = orphan_lookup_steps(&w, EXPIRY + 1);
        steps.push(Step {
            method: "getrawmempool",
            params: json!([]),
            result: Err(failure),
        });
        let rpc = Rpc::new(steps);
        assert_eq!(
            authority(rpc.clone()).expiry_snapshot(vec![w]).await,
            Err(ObservationFailure::Unavailable)
        );
        rpc.drained();
    }
}

#[tokio::test]
async fn known_orphan_observation_requires_stable_tip_and_expiry_still_passed() {
    let w = watch(true);
    let mut steps = orphan_lookup_steps(&w, EXPIRY + 1);
    steps.push(ok("getrawmempool", json!([]), json!([])));
    tip(&mut steps, EXPIRY + 2, [92; 32]);
    let rpc = Rpc::new(steps);
    assert_eq!(
        authority(rpc.clone())
            .expiry_snapshot(vec![w.clone()])
            .await,
        Err(ObservationFailure::Unavailable)
    );
    rpc.drained();

    // A held artifact seen after rollback to expiry cannot resume new payouts.
    let mut steps = orphan_lookup_steps(&w, EXPIRY);
    tip(&mut steps, EXPIRY, TIP);
    let rpc = Rpc::new(steps);
    let result = authority(rpc.clone())
        .expiry_snapshot(vec![w])
        .await
        .unwrap();
    assert_eq!(result[0].state, ExpiryChainState::Unresolved);
    rpc.drained();
}

#[tokio::test]
async fn orphan_lookup_requires_exact_bytes_id_and_strict_orphan_shape() {
    for change in 0..7 {
        let w = watch(true);
        let mut value = exact_orphan(&w);
        match change {
            0 => value["hex"] = json!("060000804e"),
            1 => value["txid"] = json!(hex::encode([9; 32])),
            2 => value["height"] = json!(0),
            3 => value["confirmations"] = json!(1),
            4 => value["blockhash"] = json!(display([0; 32])),
            5 => value["in_active_chain"] = json!("false"),
            _ => {
                assert!(value
                    .as_object_mut()
                    .unwrap()
                    .remove("confirmations")
                    .is_some());
            }
        }
        let mut steps = vec![];
        tip(&mut steps, EXPIRY + 1, TIP);
        steps.push(ok("getrawtransaction", json!([hex::encode(TX), 1]), value));
        let rpc = Rpc::new(steps);
        assert_eq!(
            authority(rpc.clone()).expiry_snapshot(vec![w]).await,
            Err(ObservationFailure::Invariant)
        );
        rpc.drained();
    }
}
