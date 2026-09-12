//! Zallet beta.3 protocol, idempotency, and crash-boundary tests.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::{
    collections::VecDeque,
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use serde_json::{json, Value};
use uuid::Uuid;
use wcash_pool_portal::{Asset, ChainNetwork, PayoutBatchRequest, PayoutOutput, ReceiverKind};
use wcash_zec_payout_signer::{
    validate_zallet_configuration, Checkpoint, CheckpointHook, JsonRpcTransport, PipelineStage,
    RpcCall, RpcTransportError, ZecFundSource, ZecPayoutError, ZecPayoutRequest, ZecPcztSigner,
    ZecSignerConfig,
};
use zcash_address::{
    unified::{Address, Encoding, Receiver},
    ToAddress, ZcashAddress,
};
use zcash_protocol::consensus::NetworkType;

const TXID: &str = "abababababababababababababababababababababababababababababababab";
const CREATED: &str = "Y3JlYXRlZA==";
const PROVED: &str = "cHJvdmVk";
const SIGNED: &str = "c2lnbmVk";
const RAW_TRANSACTION: &str = "deadbeef";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("zecwec-pczt-test-{}", Uuid::new_v4()));
        fs::create_dir(&path).expect("unique test directory can be created");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Debug)]
struct CapturedCall {
    method: &'static str,
    params: Value,
    timeout_millis: u128,
    max_response_bytes: usize,
}

#[derive(Clone, Copy)]
enum Tamper {
    None,
    FirstInspectionAmount,
    FirstInspectionAddress,
}

struct HappyZallet {
    calls: Mutex<Vec<CapturedCall>>,
    tamper: Tamper,
    inspection_count: Mutex<usize>,
    transparent_address: String,
    ironwood_address: String,
}

impl HappyZallet {
    fn new(transparent_address: String, ironwood_address: String) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            tamper: Tamper::None,
            inspection_count: Mutex::new(0),
            transparent_address,
            ironwood_address,
        }
    }

    fn tampered(transparent_address: String, ironwood_address: String, tamper: Tamper) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            tamper,
            inspection_count: Mutex::new(0),
            transparent_address,
            ironwood_address,
        }
    }

    fn calls(&self) -> Vec<CapturedCall> {
        self.calls.lock().expect("test mutex is healthy").clone()
    }

    fn inspection(&self, pczt: &str, ordinal: usize) -> Value {
        let proved = pczt != CREATED;
        let transparent_amount =
            if ordinal == 0 && matches!(self.tamper, Tamper::FirstInspectionAmount) {
                100_000_001
            } else {
                100_000_000
            };
        let transparent_address =
            if ordinal == 0 && matches!(self.tamper, Tamper::FirstInspectionAddress) {
                test_transparent_address(44)
            } else {
                self.transparent_address.clone()
            };
        json!({
            "tx_version": 6,
            "consensus_branch_id": "c8e71055",
            "expiry_height": 4_400_000,
            "privacy_policy": "AllowRevealedRecipients",
            "signing_hints": {
                "seed_fingerprint": "0123456789abcdef",
                "account_index": 0
            },
            "wallet_created": true,
            "fee_zat": 10_000,
            "transparent": {
                "inputs": [],
                "outputs": [{
                    "value_zat": transparent_amount,
                    "address": transparent_address,
                    "user_address": transparent_address
                }]
            },
            "sapling": {
                "spends": 0,
                "outputs": [],
                "value_balance_zat": 0,
                "proofs_complete": true
            },
            "orchard": {
                "actions": 0,
                "signed_actions": 0,
                "outputs": [],
                "value_balance_zat": 0,
                "proof_complete": true
            },
            "ironwood": {
                "actions": 2,
                "signed_actions": if pczt == SIGNED { 2 } else { 1 },
                "outputs": [
                    {
                        "value_zat": 200_000_000,
                        "user_address": self.ironwood_address
                    },
                    {
                        "value_zat": 50_000_000,
                        "user_address": null
                    }
                ],
                "value_balance_zat": 100_010_000,
                "proof_complete": proved
            }
        })
    }
}

impl JsonRpcTransport for HappyZallet {
    fn call(&self, call: RpcCall) -> Result<Value, RpcTransportError> {
        self.calls
            .lock()
            .expect("test mutex is healthy")
            .push(CapturedCall {
                method: call.method(),
                params: call.params().clone(),
                timeout_millis: call.timeout().as_millis(),
                max_response_bytes: call.max_response_bytes(),
            });
        match call.method() {
            "getwalletstatus" => Ok(json!({"locked": false, "extra_beta_field": true})),
            "pczt_create" => Ok(json!({
                "pczt": CREATED,
                "privacy_policy": "AllowRevealedRecipients"
            })),
            "pczt_inspect" => {
                let pczt = call.params()[0].as_str().expect("PCZT string");
                let mut count = self.inspection_count.lock().expect("test mutex is healthy");
                let result = self.inspection(pczt, *count);
                *count += 1;
                Ok(result)
            }
            "pczt_prove" => Ok(json!({
                "pczt": PROVED,
                "sapling_proven": false,
                "orchard_proven": false,
                "ironwood_proven": true
            })),
            "pczt_sign" => Ok(json!({
                "pczt": SIGNED,
                "transparent_signed": 0,
                "sapling_signed": 0,
                "orchard_signed": 0,
                "ironwood_signed": 1,
                "unsigned_transparent": [],
                "unsigned_sapling": [],
                "unsigned_orchard": [],
                "unsigned_ironwood": []
            })),
            "pczt_extract" => Ok(json!({
                "hex": RAW_TRANSACTION,
                "txid": TXID,
                "stored": true
            })),
            method => panic!("unexpected wallet method {method}"),
        }
    }
}

enum ZebraStep {
    Accepted,
    AlreadyKnown,
    Rejected,
    Timeout,
    WrongTransactionId,
}

struct ScriptedZebra {
    steps: Mutex<VecDeque<ZebraStep>>,
    calls: Mutex<Vec<CapturedCall>>,
}

impl ScriptedZebra {
    fn new(steps: impl IntoIterator<Item = ZebraStep>) -> Self {
        Self {
            steps: Mutex::new(steps.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<CapturedCall> {
        self.calls.lock().expect("test mutex is healthy").clone()
    }
}

impl JsonRpcTransport for ScriptedZebra {
    fn call(&self, call: RpcCall) -> Result<Value, RpcTransportError> {
        self.calls
            .lock()
            .expect("test mutex is healthy")
            .push(CapturedCall {
                method: call.method(),
                params: call.params().clone(),
                timeout_millis: call.timeout().as_millis(),
                max_response_bytes: call.max_response_bytes(),
            });
        assert_eq!(call.method(), "sendrawtransaction");
        match self
            .steps
            .lock()
            .expect("test mutex is healthy")
            .pop_front()
            .unwrap_or(ZebraStep::AlreadyKnown)
        {
            ZebraStep::Accepted => Ok(Value::String(TXID.to_owned())),
            ZebraStep::AlreadyKnown => Err(RpcTransportError::server(
                -27,
                "transaction already in block chain",
            )),
            ZebraStep::Rejected => Err(RpcTransportError::server(-26, "transaction rejected")),
            ZebraStep::Timeout => Err(RpcTransportError::timeout()),
            ZebraStep::WrongTransactionId => Ok(Value::String("cd".repeat(32))),
        }
    }
}

struct InterruptOnce {
    target: Checkpoint,
    fired: AtomicBool,
}

impl CheckpointHook for InterruptOnce {
    fn should_interrupt(&self, checkpoint: Checkpoint) -> bool {
        checkpoint == self.target && !self.fired.swap(true, Ordering::SeqCst)
    }
}

fn test_transparent_address(byte: u8) -> String {
    ZcashAddress::from_transparent_p2pkh(NetworkType::Test, [byte; 20]).encode()
}

fn test_ironwood_address(byte: u8) -> String {
    let address = Address::try_from_items(vec![Receiver::Orchard([byte; 43])])
        .expect("valid Orchard receiver");
    ZcashAddress::from_unified(NetworkType::Test, address).encode()
}

fn write_wallet_config(root: &Path, overrides: Option<&str>) -> PathBuf {
    let config = root.join("zallet.toml");
    let contents = overrides.unwrap_or(
        r#"[consensus]
network = "test"

[external]
broadcast = false

[features]
as_of_version = "0.1.0-beta.3"

[rpc]
bind = ["127.0.0.1:28232", "[::1]:28232"]
"#,
    );
    fs::write(&config, contents).expect("test configuration can be written");
    #[cfg(unix)]
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600))
        .expect("test configuration permissions can be restricted");
    config
}

fn fixture(root: &TestDirectory) -> (ZecSignerConfig, ZecPayoutRequest, String, String) {
    let account = Uuid::new_v4();
    let transparent = test_transparent_address(7);
    let ironwood = test_ironwood_address(9);
    let config_path = write_wallet_config(root.path(), None);
    let config = ZecSignerConfig::new(root.path().join("journal"), config_path, account)
        .expect("valid test signer configuration");
    let request = ZecPayoutRequest {
        batch: PayoutBatchRequest {
            batch_id: Uuid::new_v4(),
            asset: Asset::Zec,
            network: ChainNetwork::Testnet,
            ledger_root: [5; 32],
            reconciliation_id: Uuid::new_v4(),
            outputs: vec![
                PayoutOutput {
                    allocation_id: Uuid::new_v4(),
                    canonical_address: transparent.clone(),
                    receiver_kind: ReceiverKind::Transparent,
                    amount_zat: 100_000_000,
                },
                PayoutOutput {
                    allocation_id: Uuid::new_v4(),
                    canonical_address: ironwood.clone(),
                    receiver_kind: ReceiverKind::Ironwood,
                    amount_zat: 200_000_000,
                },
            ],
        },
        source_account: account,
        fund_source: ZecFundSource::Orchard,
    };
    (config, request, transparent, ironwood)
}

#[test]
fn beta_three_rpc_pipeline_is_exact_and_replay_is_side_effect_free() {
    let root = TestDirectory::new();
    let (config, request, transparent, ironwood) = fixture(&root);
    let zallet = Arc::new(HappyZallet::new(transparent.clone(), ironwood.clone()));
    let zebra = Arc::new(ScriptedZebra::new([ZebraStep::Accepted]));
    let signer =
        ZecPcztSigner::new(config, zallet.clone(), zebra.clone()).expect("safe signer can start");

    signer.readiness().expect("wallet is ready");
    let receipt = signer.execute(&request).expect("payout succeeds");
    assert_eq!(receipt.batch_id, request.batch.batch_id);
    assert_eq!(receipt.transaction_id, TXID);
    assert_eq!(receipt.output_total_zat, 300_000_000);
    assert_eq!(receipt.intent_digest, request.batch.commitment().unwrap());
    assert_eq!(receipt.transaction_id_bytes, [0xab; 32]);
    assert_eq!(receipt.signed_transaction, vec![0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(receipt.network_fee_zat, 10_000);

    let call_count = zallet.calls().len() + zebra.calls().len();
    assert_eq!(signer.execute(&request).expect("exact replay"), receipt);
    assert_eq!(zallet.calls().len() + zebra.calls().len(), call_count);

    let calls = zallet.calls();
    assert_eq!(
        calls.iter().map(|call| call.method).collect::<Vec<_>>(),
        vec![
            "getwalletstatus",
            "pczt_create",
            "pczt_inspect",
            "pczt_prove",
            "pczt_inspect",
            "pczt_sign",
            "pczt_inspect",
            "pczt_extract"
        ]
    );
    assert_eq!(calls[1].params[0], request.source_account.to_string());
    assert_eq!(calls[1].params[1][0]["address"], transparent);
    assert_eq!(calls[1].params[1][0]["amount"].to_string(), "1.00000000");
    assert_eq!(calls[1].params[1][1]["address"], ironwood);
    assert_eq!(calls[1].params[1][1]["amount"].to_string(), "2.00000000");
    assert_eq!(calls[1].params[2], 100);
    assert_eq!(calls[1].params[3], "NoPrivacy");
    assert_eq!(calls[1].params[4], "orchard");
    assert_eq!(
        calls[5].params,
        json!([PROVED, "AllowRevealedRecipients", true])
    );
    assert!(calls[3].timeout_millis > calls[1].timeout_millis);
    assert!(calls.iter().all(|call| call.max_response_bytes > 0));
    assert_eq!(zebra.calls()[0].params, json!([RAW_TRANSACTION]));
}

#[test]
fn every_external_and_durable_boundary_resumes_to_the_same_transaction() {
    let checkpoints = [
        Checkpoint::StagePersisted(PipelineStage::Reserved),
        Checkpoint::RpcReturned(PipelineStage::Created),
        Checkpoint::StagePersisted(PipelineStage::Created),
        Checkpoint::RpcReturned(PipelineStage::CreatedVerified),
        Checkpoint::StagePersisted(PipelineStage::CreatedVerified),
        Checkpoint::RpcReturned(PipelineStage::Proved),
        Checkpoint::StagePersisted(PipelineStage::Proved),
        Checkpoint::RpcReturned(PipelineStage::ProvedVerified),
        Checkpoint::StagePersisted(PipelineStage::ProvedVerified),
        Checkpoint::RpcReturned(PipelineStage::Signed),
        Checkpoint::StagePersisted(PipelineStage::Signed),
        Checkpoint::RpcReturned(PipelineStage::SignedVerified),
        Checkpoint::StagePersisted(PipelineStage::SignedVerified),
        Checkpoint::RpcReturned(PipelineStage::Extracted),
        Checkpoint::StagePersisted(PipelineStage::Extracted),
        Checkpoint::RpcReturned(PipelineStage::Completed),
        Checkpoint::StagePersisted(PipelineStage::Completed),
    ];

    for checkpoint in checkpoints {
        let root = TestDirectory::new();
        let (config, request, transparent, ironwood) = fixture(&root);
        let zallet = Arc::new(HappyZallet::new(transparent, ironwood));
        let zebra = Arc::new(ScriptedZebra::new([
            ZebraStep::Accepted,
            ZebraStep::AlreadyKnown,
        ]));
        let hook = Arc::new(InterruptOnce {
            target: checkpoint,
            fired: AtomicBool::new(false),
        });
        let interrupted = ZecPcztSigner::new(config.clone(), zallet.clone(), zebra.clone())
            .expect("safe signer")
            .with_checkpoint_hook(hook);
        assert_eq!(
            interrupted.execute(&request),
            Err(ZecPayoutError::Interrupted),
            "checkpoint {checkpoint:?}"
        );

        let resumed = ZecPcztSigner::new(config, zallet, zebra.clone()).expect("restart signer");
        assert_eq!(
            resumed
                .execute(&request)
                .expect("restart completes exact payout")
                .transaction_id,
            TXID,
            "checkpoint {checkpoint:?}"
        );
        let broadcast_calls = zebra.calls();
        assert!(
            broadcast_calls
                .iter()
                .all(|call| call.params == json!([RAW_TRANSACTION])),
            "checkpoint {checkpoint:?}"
        );
    }
}

#[test]
fn altered_inspection_never_reaches_proving() {
    for tamper in [
        Tamper::FirstInspectionAmount,
        Tamper::FirstInspectionAddress,
    ] {
        let root = TestDirectory::new();
        let (config, request, transparent, ironwood) = fixture(&root);
        let zallet = Arc::new(HappyZallet::tampered(transparent, ironwood, tamper));
        let zebra = Arc::new(ScriptedZebra::new([]));
        let signer =
            ZecPcztSigner::new(config, zallet.clone(), zebra).expect("safe signer can start");
        assert_eq!(
            signer.execute(&request),
            Err(ZecPayoutError::WalletProtocolViolation)
        );
        assert!(!zallet
            .calls()
            .iter()
            .any(|call| call.method == "pczt_prove"));
    }
}

#[test]
fn network_asset_account_and_fund_source_are_independently_fenced() {
    let root = TestDirectory::new();
    let (config, request, transparent, ironwood) = fixture(&root);
    let zallet = Arc::new(HappyZallet::new(transparent, ironwood));
    let zebra = Arc::new(ScriptedZebra::new([]));
    let signer = ZecPcztSigner::new(config, zallet.clone(), zebra).expect("safe signer");

    let mut wrong_network = request.clone();
    wrong_network.batch.network = ChainNetwork::Mainnet;
    assert_eq!(
        signer.execute(&wrong_network),
        Err(ZecPayoutError::WrongNetwork)
    );

    let mut wrong_asset = request.clone();
    wrong_asset.batch.asset = Asset::Wec;
    assert_eq!(
        signer.execute(&wrong_asset),
        Err(ZecPayoutError::WrongAsset)
    );

    let mut wrong_account = request.clone();
    wrong_account.source_account = Uuid::new_v4();
    assert_eq!(
        signer.execute(&wrong_account),
        Err(ZecPayoutError::WrongAccount)
    );

    let mut wrong_source = request;
    wrong_source.fund_source = ZecFundSource::Sapling;
    assert_eq!(
        signer.execute(&wrong_source),
        Err(ZecPayoutError::WrongFundSource)
    );
    assert!(zallet.calls().is_empty());
}

#[test]
fn reused_batch_id_with_changed_facts_is_rejected_without_rpc() {
    let root = TestDirectory::new();
    let (config, request, transparent, ironwood) = fixture(&root);
    let zallet = Arc::new(HappyZallet::new(transparent, ironwood));
    let zebra = Arc::new(ScriptedZebra::new([ZebraStep::Accepted]));
    let signer = ZecPcztSigner::new(config, zallet.clone(), zebra.clone()).expect("safe signer");
    signer.execute(&request).expect("first payout");
    let call_count = zallet.calls().len() + zebra.calls().len();

    let mut conflict = request;
    conflict.batch.outputs[0].amount_zat += 1;
    assert_eq!(
        signer.execute(&conflict),
        Err(ZecPayoutError::IdempotencyConflict)
    );
    assert_eq!(zallet.calls().len() + zebra.calls().len(), call_count);
}

#[test]
fn timeout_retries_identical_bytes_and_already_known_resolves_success() {
    let root = TestDirectory::new();
    let (config, request, transparent, ironwood) = fixture(&root);
    let zallet = Arc::new(HappyZallet::new(transparent, ironwood));
    let zebra = Arc::new(ScriptedZebra::new([
        ZebraStep::Timeout,
        ZebraStep::AlreadyKnown,
    ]));
    let signer = ZecPcztSigner::new(config, zallet, zebra.clone()).expect("safe signer");

    assert_eq!(
        signer.execute(&request),
        Err(ZecPayoutError::BroadcastAmbiguous)
    );
    assert_eq!(
        signer
            .execute(&request)
            .expect("known exact tx")
            .transaction_id,
        TXID
    );
    let calls = zebra.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].params, calls[1].params);
}

#[test]
fn explicit_rejection_is_terminal_and_wrong_txid_is_ambiguous() {
    let root = TestDirectory::new();
    let (config, request, transparent, ironwood) = fixture(&root);
    let zallet = Arc::new(HappyZallet::new(transparent, ironwood));
    let zebra = Arc::new(ScriptedZebra::new([ZebraStep::Rejected]));
    let signer = ZecPcztSigner::new(config, zallet, zebra.clone()).expect("safe signer");
    assert_eq!(
        signer.execute(&request),
        Err(ZecPayoutError::BroadcastRejected)
    );
    assert_eq!(
        signer.execute(&request),
        Err(ZecPayoutError::BroadcastRejected)
    );
    assert_eq!(zebra.calls().len(), 1);

    let second_root = TestDirectory::new();
    let (config, request, transparent, ironwood) = fixture(&second_root);
    let zallet = Arc::new(HappyZallet::new(transparent, ironwood));
    let zebra = Arc::new(ScriptedZebra::new([
        ZebraStep::WrongTransactionId,
        ZebraStep::Accepted,
    ]));
    let signer = ZecPcztSigner::new(config, zallet, zebra).expect("safe signer");
    assert_eq!(
        signer.execute(&request),
        Err(ZecPayoutError::BroadcastAmbiguous)
    );
    assert!(signer.execute(&request).is_ok());
}

#[test]
fn unsafe_wallet_configuration_is_rejected_before_rpc() {
    let cases = [
        r#"[consensus]
network="main"
[external]
broadcast=false
[features]
as_of_version="0.1.0-beta.3"
[rpc]
bind=["127.0.0.1:1"]
"#,
        r#"[consensus]
network="test"
[external]
broadcast=true
[features]
as_of_version="0.1.0-beta.3"
[rpc]
bind=["127.0.0.1:1"]
"#,
        r#"[consensus]
network="test"
[external]
broadcast=false
[features]
as_of_version="0.1.0-beta.2"
[rpc]
bind=["127.0.0.1:1"]
"#,
        r#"[consensus]
network="test"
[external]
broadcast=false
[features]
as_of_version="0.1.0-beta.3"
[rpc]
bind=["0.0.0.0:1"]
"#,
    ];
    for contents in cases {
        let root = TestDirectory::new();
        let config = write_wallet_config(root.path(), Some(contents));
        assert_eq!(
            validate_zallet_configuration(&config),
            Err(ZecPayoutError::UnsafeWalletConfiguration)
        );
    }
}
