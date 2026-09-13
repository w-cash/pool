//! Zallet beta.3 protocol, idempotency, and crash-boundary tests.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use incrementalmerkletree::{Hashable, Level};
use orchard::{
    circuit::{OrchardCircuitVersion, ProvingKey},
    keys::SpendAuthorizingKey,
    note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Note,
};
use pczt::{
    roles::{
        creator::Creator, io_finalizer::IoFinalizer, prover::Prover, signer::Signer as PcztSigner,
        tx_extractor::TransactionExtractor, updater::Updater,
    },
    Pczt,
};
use rand_core::{CryptoRng, Error as RngError, RngCore};
use serde::{Deserialize, Serialize};
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
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedSpendingKey};
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding},
    fees::zip317,
    Authorized, Transaction, TransactionData,
};
use zcash_protocol::{
    consensus::{BlockHeight, NetworkType, TEST_NETWORK},
    memo::MemoBytes,
    value::Zatoshis,
};
use zcash_transparent::address::TransparentAddress;
use zip32::{fingerprint::SeedFingerprint, AccountId, ChildIndex};

const NU6_3_BRANCH_ID: u32 = 0x37a5_165b;
const EXPIRY_HEIGHT: u32 = 4_400_000;
const SOURCE_SEED: [u8; 32] = [0x11; 32];
const RECIPIENT_SEED: [u8; 32] = [0x22; 32];
const PAYOUT_ZAT: u64 = 200_000_000;
const FEE_ZAT: u64 = 10_000;

fn with_stage(pczt: &str, stage: &str) -> String {
    let encoded = BASE64_STANDARD.decode(pczt).expect("test PCZT is base64");
    let pczt = Pczt::parse(&encoded).expect("test PCZT parses");
    let pczt = Updater::new(pczt)
        .update_global_with(|mut global| {
            global.set_proprietary("zecwec.test.stage".to_owned(), stage.as_bytes().to_vec());
        })
        .finish();
    BASE64_STANDARD.encode(pczt.serialize().expect("test PCZT serializes"))
}

fn expected_effects_digest(pczt: &str) -> [u8; 32] {
    let bytes = BASE64_STANDARD.decode(pczt).expect("test PCZT is base64");
    PcztSigner::new(Pczt::parse(&bytes).expect("test PCZT parses"))
        .expect("test PCZT exposes transaction effects")
        .shielded_sighash()
}

#[derive(Clone)]
struct TestPczt {
    created: String,
    proved: String,
    signed: String,
    altered: String,
    altered_recipient: String,
    altered_value: String,
    wrong_coin_type: String,
    empty: String,
    raw_transaction: String,
    transaction_id: String,
    altered_raw_transaction: String,
    altered_transaction_id: String,
    source_seed_fingerprint: SeedFingerprint,
    source_unified_address: String,
    source_ufvk: String,
    recipient_unified_address: String,
    recipient_kind: ReceiverKind,
    fee_zat: u64,
    extra_recipient: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct PcztV2GlobalWire {
    tx_version: u32,
    version_group_id: u32,
    consensus_branch_id: u32,
    fallback_lock_time: Option<u32>,
    expiry_height: u32,
    coin_type: u32,
    tx_modifiable: u8,
    proprietary: BTreeMap<String, Vec<u8>>,
}

fn with_coin_type(pczt_base64: &str, coin_type: u32) -> String {
    let encoded = BASE64_STANDARD
        .decode(pczt_base64)
        .expect("test PCZT is base64");
    let body = encoded
        .strip_prefix(b"PCZT\x02\0\0\0")
        .expect("Ironwood test PCZT uses v2");
    let (mut global, remainder) =
        postcard::take_from_bytes::<PcztV2GlobalWire>(body).expect("test global decodes");
    global.coin_type = coin_type;
    let mut rewritten = b"PCZT\x02\0\0\0".to_vec();
    rewritten = postcard::to_extend(&global, rewritten).expect("test global re-encodes");
    rewritten.extend_from_slice(remainder);
    Pczt::parse(&rewritten).expect("rewritten test PCZT parses");
    BASE64_STANDARD.encode(rewritten)
}

fn extract_transaction(pczt_base64: &str) -> (String, String) {
    let encoded = BASE64_STANDARD
        .decode(pczt_base64)
        .expect("test PCZT is base64");
    let transaction = TransactionExtractor::new(Pczt::parse(&encoded).expect("test PCZT parses"))
        .extract()
        .expect("proved and signed test PCZT extracts");
    let transaction_id = transaction.txid().to_string();
    let mut raw = Vec::new();
    transaction
        .write(&mut raw)
        .expect("test transaction writes");
    (hex::encode(raw), transaction_id)
}

fn unrelated_transaction() -> (String, String) {
    let transaction = TransactionData::<Authorized>::from_parts_v6(
        zcash_protocol::consensus::BranchId::Nu6_3,
        0,
        BlockHeight::from_u32(EXPIRY_HEIGHT),
        None,
        None,
        None,
        None,
    )
    .freeze()
    .expect("empty V6 test transaction freezes");
    let transaction_id = transaction.txid().to_string();
    let mut raw = Vec::new();
    transaction
        .write(&mut raw)
        .expect("empty V6 test transaction writes");
    (hex::encode(raw), transaction_id)
}

fn ironwood_proving_key() -> &'static ProvingKey {
    static PROVING_KEY: OnceLock<ProvingKey> = OnceLock::new();
    PROVING_KEY.get_or_init(|| ProvingKey::build(OrchardCircuitVersion::PostNu6_3))
}

fn prove_and_sign(pczt_base64: &str, spend_action_index: usize) -> (String, String) {
    let encoded = BASE64_STANDARD
        .decode(pczt_base64)
        .expect("test PCZT is base64");
    let proved = Prover::new(Pczt::parse(&encoded).expect("test PCZT parses"))
        .create_ironwood_proof(ironwood_proving_key())
        .expect("test Ironwood proof is created")
        .finish();
    let proved = with_stage(
        &BASE64_STANDARD.encode(proved.serialize().expect("proved PCZT serializes")),
        "proved",
    );

    let source_usk = UnifiedSpendingKey::from_seed(&TEST_NETWORK, &SOURCE_SEED, AccountId::ZERO)
        .expect("source test key derives");
    let ask = SpendAuthorizingKey::from(source_usk.orchard());
    let encoded = BASE64_STANDARD
        .decode(&proved)
        .expect("proved test PCZT is base64");
    let mut signer = PcztSigner::new(Pczt::parse(&encoded).expect("proved test PCZT parses"))
        .expect("proved test PCZT is signable");
    signer
        .sign_ironwood(spend_action_index, &ask)
        .expect("test Ironwood spend signs");
    let signed = with_stage(
        &BASE64_STANDARD.encode(signer.finish().serialize().expect("signed PCZT serializes")),
        "signed",
    );
    (proved, signed)
}

#[derive(Clone, Copy)]
struct DeterministicRng(u64);

impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        rand_core::impls::fill_bytes_via_next(self, destination);
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for DeterministicRng {}

fn valid_ironwood_note(recipient: orchard::Address, value: u64) -> Note {
    for counter in 1u64.. {
        let mut rho_bytes = [0; 32];
        rho_bytes[..8].copy_from_slice(&counter.to_le_bytes());
        let Some(rho) = Option::<Rho>::from(Rho::from_bytes(&rho_bytes)) else {
            continue;
        };
        for seed_counter in 1u64.. {
            let mut seed_bytes = [0; 32];
            seed_bytes[..8].copy_from_slice(&seed_counter.to_le_bytes());
            let Some(rseed) = Option::<RandomSeed>::from(RandomSeed::from_bytes(seed_bytes, &rho))
            else {
                continue;
            };
            if let Some(note) = Option::<Note>::from(Note::from_parts(
                recipient,
                NoteValue::from_raw(value),
                rho,
                rseed,
                NoteVersion::V3,
            )) {
                return note;
            }
        }
    }
    unreachable!("the finite-field encodings contain valid test values")
}

fn build_effects_pczt(expiry_height: u32) -> (String, TestPcztIdentity) {
    build_effects_pczt_for(expiry_height, &RECIPIENT_SEED, PAYOUT_ZAT)
}

fn build_effects_pczt_for(
    expiry_height: u32,
    recipient_seed: &[u8; 32],
    payout_zat: u64,
) -> (String, TestPcztIdentity) {
    build_destination_pczt(expiry_height, recipient_seed, payout_zat, None)
}

fn build_destination_pczt(
    expiry_height: u32,
    recipient_seed: &[u8; 32],
    payout_zat: u64,
    transparent: Option<TransparentAddress>,
) -> (String, TestPcztIdentity) {
    build_outputs_pczt(
        expiry_height,
        recipient_seed,
        payout_zat,
        transparent,
        false,
    )
}

fn build_outputs_pczt(
    expiry_height: u32,
    recipient_seed: &[u8; 32],
    payout_zat: u64,
    transparent: Option<TransparentAddress>,
    extra_output: bool,
) -> (String, TestPcztIdentity) {
    let account_index = AccountId::ZERO;
    let source_usk = UnifiedSpendingKey::from_seed(&TEST_NETWORK, &SOURCE_SEED, account_index)
        .expect("source test key derives");
    let source_ufvk = source_usk.to_unified_full_viewing_key();
    let source_orchard_fvk = source_ufvk
        .orchard()
        .cloned()
        .expect("source key contains Orchard");
    let (source_address, _) = source_ufvk
        .default_address(UnifiedAddressRequest::ORCHARD)
        .expect("source Orchard-only UA derives");

    let recipient_usk = UnifiedSpendingKey::from_seed(&TEST_NETWORK, recipient_seed, account_index)
        .expect("recipient test key derives");
    let recipient_ufvk = recipient_usk.to_unified_full_viewing_key();
    let (recipient_address, _) = recipient_ufvk
        .default_address(UnifiedAddressRequest::ORCHARD)
        .expect("recipient Orchard-only UA derives");
    let recipient = *recipient_address
        .orchard()
        .expect("recipient contains Orchard receiver");

    let extra_usk =
        UnifiedSpendingKey::from_seed(&TEST_NETWORK, &[0x66; 32], account_index).unwrap();
    let (extra_address, _) = extra_usk
        .to_unified_full_viewing_key()
        .default_address(UnifiedAddressRequest::ORCHARD)
        .unwrap();
    let fee_zat = FEE_ZAT;
    let source_note = valid_ironwood_note(
        source_address.orchard().copied().unwrap(),
        payout_zat * if extra_output { 2 } else { 1 } + fee_zat,
    );
    let source_commitment: ExtractedNoteCommitment = source_note.commitment().into();
    let merkle_path = MerklePath::from_parts(
        0,
        std::array::from_fn(|level| MerkleHashOrchard::empty_root(Level::from(level as u8))),
    );
    let ironwood_anchor = merkle_path.root(source_commitment);
    let target_height = BlockHeight::from_u32(expiry_height - 40);
    let mut builder = Builder::new(
        TEST_NETWORK,
        target_height,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(ironwood_anchor),
            orchard_padding: BundlePadding::UNPADDED,
            ironwood_padding: BundlePadding::UNPADDED,
        },
    )
    .with_expiry_height(BlockHeight::from_u32(expiry_height));
    builder
        .add_ironwood_spend::<zip317::FeeError>(source_orchard_fvk, source_note, merkle_path)
        .expect("valid Ironwood source note");
    if let Some(transparent) = transparent {
        builder
            .add_transparent_output(&transparent, Zatoshis::const_from_u64(payout_zat))
            .expect("valid transparent payout");
    } else {
        builder
            .add_ironwood_output::<zip317::FeeError>(
                None,
                recipient,
                Zatoshis::const_from_u64(payout_zat),
                MemoBytes::empty(),
            )
            .expect("valid Ironwood payout");
    }
    if extra_output {
        builder
            .add_ironwood_output::<zip317::FeeError>(
                None,
                *extra_address.orchard().unwrap(),
                Zatoshis::const_from_u64(payout_zat),
                MemoBytes::empty(),
            )
            .expect("second valid shielded payout");
    }
    let build = builder
        .build_for_pczt(DeterministicRng(0x5ec0_1a7e), &zip317::FeeRule::standard())
        .expect("balanced PCZT fixture");
    let spend_index = build
        .ironwood_meta
        .spend_action_index(0)
        .expect("source spend action exists");
    let output_index = if transparent.is_none() {
        build.ironwood_meta.output_action_index(0)
    } else {
        None
    };
    let extra_index = if extra_output {
        build
            .ironwood_meta
            .output_action_index(usize::from(transparent.is_none()))
    } else {
        None
    };
    let pczt = Creator::build_from_parts(build.pczt_parts).expect("V6 PCZT parts");
    let pczt = IoFinalizer::new(pczt)
        .finalize_io()
        .expect("fixture IO finalizes");
    let seed_fingerprint = SeedFingerprint::from_seed(&SOURCE_SEED).expect("valid ZIP 32 seed");
    let derivation = orchard::pczt::Zip32Derivation::parse(
        seed_fingerprint.to_bytes(),
        vec![
            ChildIndex::hardened(32).index(),
            ChildIndex::hardened(1).index(),
            ChildIndex::hardened(u32::from(account_index)).index(),
        ],
    )
    .expect("standard Orchard ZIP 32 derivation");
    let recipient_encoded = match transparent {
        Some(TransparentAddress::PublicKeyHash(hash)) => {
            ZcashAddress::from_transparent_p2pkh(NetworkType::Test, hash).encode()
        }
        Some(TransparentAddress::ScriptHash(hash)) => {
            ZcashAddress::from_transparent_p2sh(NetworkType::Test, hash).encode()
        }
        None => recipient_address.encode(&TEST_NETWORK),
    };
    let privacy_policy = if transparent.is_some() {
        "AllowRevealedRecipients"
    } else {
        "FullPrivacy"
    };
    let pczt = Updater::new(pczt)
        .update_global_with(|mut global| {
            global.set_proprietary(
                "zallet.v1.seed_fingerprint".to_owned(),
                seed_fingerprint.to_bytes().to_vec(),
            );
            global.set_proprietary(
                "zallet.v1.account_index".to_owned(),
                u32::from(account_index).to_le_bytes().to_vec(),
            );
            global.set_proprietary(
                "zallet.v1.privacy_policy".to_owned(),
                privacy_policy.as_bytes().to_vec(),
            );
            global.set_proprietary("zcash_client_backend:proposal_info".to_owned(), vec![1]);
        })
        .update_ironwood_with(|mut bundle| {
            bundle.update_action_with(spend_index, |mut action| {
                action.set_spend_zip32_derivation(derivation);
                Ok(())
            })?;
            if let Some(output_index) = output_index {
                bundle.update_action_with(output_index, |mut action| {
                    action.set_output_user_address(recipient_encoded.clone());
                    Ok(())
                })?;
            }
            if let Some(extra_index) = extra_index {
                bundle.update_action_with(extra_index, |mut action| {
                    action.set_output_user_address(extra_address.encode(&TEST_NETWORK));
                    Ok(())
                })?;
            }
            Ok(())
        })
        .expect("Ironwood metadata updates")
        .finish();
    let pczt = if transparent.is_some() {
        Updater::new(pczt)
            .update_transparent_with(|mut bundle| {
                bundle.update_output_with(0, |mut output| {
                    output.set_user_address(recipient_encoded.clone());
                    Ok(())
                })
            })
            .expect("transparent metadata updates")
            .finish()
    } else {
        pczt
    };
    let encoded = BASE64_STANDARD.encode(pczt.serialize().expect("fixture PCZT serializes"));
    (
        encoded,
        TestPcztIdentity {
            source_seed_fingerprint: seed_fingerprint,
            source_unified_address: source_address.encode(&TEST_NETWORK),
            source_ufvk: source_ufvk.encode(&TEST_NETWORK),
            recipient_unified_address: recipient_encoded,
            spend_action_index: spend_index,
            extra_recipient: extra_output.then(|| extra_address.encode(&TEST_NETWORK)),
        },
    )
}

struct TestPcztIdentity {
    source_seed_fingerprint: SeedFingerprint,
    source_unified_address: String,
    source_ufvk: String,
    recipient_unified_address: String,
    spend_action_index: usize,
    extra_recipient: Option<String>,
}

fn test_pczt() -> TestPczt {
    static FIXTURE: OnceLock<TestPczt> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let (base, identity) = build_effects_pczt(EXPIRY_HEIGHT);
            let (altered, _) = build_effects_pczt(EXPIRY_HEIGHT + 1);
            let (altered_recipient, _) =
                build_effects_pczt_for(EXPIRY_HEIGHT, &[0x33; 32], PAYOUT_ZAT);
            let (altered_value, _) =
                build_effects_pczt_for(EXPIRY_HEIGHT, &RECIPIENT_SEED, PAYOUT_ZAT + 1);
            let empty = Creator::new(NU6_3_BRANCH_ID, EXPIRY_HEIGHT, 1, None, None)
                .expect("NU6.3 PCZT creator")
                .build()
                .expect("empty PCZT");
            let empty = BASE64_STANDARD.encode(empty.serialize().expect("empty PCZT serializes"));
            let created = with_stage(&base, "created");
            let (proved, signed) = prove_and_sign(&created, identity.spend_action_index);
            let altered = with_stage(&altered, "altered");
            let altered_recipient = with_stage(&altered_recipient, "altered_recipient");
            let altered_value = with_stage(&altered_value, "altered_value");
            let wrong_coin_type = with_coin_type(&created, 133);
            let (raw_transaction, transaction_id) = extract_transaction(&signed);
            let (altered_raw_transaction, altered_transaction_id) = unrelated_transaction();
            TestPczt {
                created,
                proved,
                signed,
                altered,
                altered_recipient,
                altered_value,
                wrong_coin_type,
                empty,
                raw_transaction,
                transaction_id,
                altered_raw_transaction,
                altered_transaction_id,
                source_seed_fingerprint: identity.source_seed_fingerprint,
                source_unified_address: identity.source_unified_address,
                source_ufvk: identity.source_ufvk,
                recipient_unified_address: identity.recipient_unified_address,
                recipient_kind: ReceiverKind::Ironwood,
                fee_zat: FEE_ZAT,
                extra_recipient: None,
            }
        })
        .clone()
}

fn transparent_test_pczt(script_hash: bool) -> TestPczt {
    static P2PKH: OnceLock<TestPczt> = OnceLock::new();
    static P2SH: OnceLock<TestPczt> = OnceLock::new();
    (if script_hash { &P2SH } else { &P2PKH })
        .get_or_init(|| {
            let destination = if script_hash {
                TransparentAddress::ScriptHash([0x33; 20])
            } else {
                TransparentAddress::PublicKeyHash([0x44; 20])
            };
            let (created, identity) = build_destination_pczt(
                EXPIRY_HEIGHT,
                &RECIPIENT_SEED,
                PAYOUT_ZAT,
                Some(destination),
            );
            let (proved, signed) = prove_and_sign(&created, identity.spend_action_index);
            let (raw_transaction, transaction_id) = extract_transaction(&signed);
            TestPczt {
                created,
                proved,
                signed,
                raw_transaction,
                transaction_id,
                recipient_unified_address: identity.recipient_unified_address,
                recipient_kind: ReceiverKind::Transparent,
                fee_zat: FEE_ZAT,
                ..test_pczt()
            }
        })
        .clone()
}

fn multiple_recipient_pczt() -> TestPczt {
    static FIXTURE: OnceLock<TestPczt> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let (created, identity) =
                build_outputs_pczt(EXPIRY_HEIGHT, &RECIPIENT_SEED, PAYOUT_ZAT, None, true);
            let (proved, signed) = prove_and_sign(&created, identity.spend_action_index);
            let (raw_transaction, transaction_id) = extract_transaction(&signed);
            TestPczt {
                created,
                proved,
                signed,
                raw_transaction,
                transaction_id,
                extra_recipient: identity.extra_recipient,
                fee_zat: FEE_ZAT,
                ..test_pczt()
            }
        })
        .clone()
}

fn mixed_recipient_pczt() -> TestPczt {
    static FIXTURE: OnceLock<TestPczt> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let (created, identity) = build_outputs_pczt(
                EXPIRY_HEIGHT,
                &RECIPIENT_SEED,
                PAYOUT_ZAT,
                Some(TransparentAddress::PublicKeyHash([0x77; 20])),
                true,
            );
            let (proved, signed) = prove_and_sign(&created, identity.spend_action_index);
            let (raw_transaction, transaction_id) = extract_transaction(&signed);
            TestPczt {
                created,
                proved,
                signed,
                raw_transaction,
                transaction_id,
                recipient_unified_address: identity.recipient_unified_address,
                recipient_kind: ReceiverKind::Transparent,
                extra_recipient: identity.extra_recipient,
                fee_zat: FEE_ZAT,
                ..test_pczt()
            }
        })
        .clone()
}

fn healthy_status() -> Value {
    json!({
        "node_tip": {
            "blockhash": "11".repeat(32),
            "height": EXPIRY_HEIGHT - 20
        },
        "wallet_tip": {
            "blockhash": "11".repeat(32),
            "height": EXPIRY_HEIGHT - 20
        },
        "fully_synced_height": EXPIRY_HEIGHT - 20,
        "locked": false
    })
}

fn healthy_account(account_uuid: Value, pczt: &TestPczt) -> Value {
    json!({
        "account_uuid": account_uuid,
        "name": "ZecWec collector",
        "seedfp": pczt.source_seed_fingerprint.to_string(),
        "zip32_account_index": 0,
        "addresses": [{
            "diversifier_index": 0,
            "ua": pczt.source_unified_address
        }]
    })
}

fn healthy_balances(account_uuid: Value) -> Value {
    json!({
        "accounts": [{
            "account_uuid": account_uuid,
            "ironwood": {
                "spendable": {"valueZat": PAYOUT_ZAT + FEE_ZAT}
            },
            "total": {
                "spendable": {"valueZat": PAYOUT_ZAT + FEE_ZAT}
            }
        }]
    })
}

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
    WeakPrivacyPolicy,
    DuplicateInspectionRecipient,
    EmptyCreatedEffects,
    CreatedRecipientEffects,
    CreatedValueEffects,
    MainnetCoinType,
    FirstInspectionAmount,
    FirstInspectionAddress,
    ProvedEffects,
    SignedEffects,
    MissingSignedAuthorization,
    ExtractedEffects,
}

struct HappyZallet {
    calls: Mutex<Vec<CapturedCall>>,
    tamper: Tamper,
    inspection_count: Mutex<usize>,
    pczt: TestPczt,
}

impl HappyZallet {
    fn privacy_policy(&self) -> &'static str {
        match self.pczt.recipient_kind {
            ReceiverKind::Transparent => "AllowRevealedRecipients",
            ReceiverKind::Ironwood => "FullPrivacy",
        }
    }

    fn new(pczt: TestPczt) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            tamper: Tamper::None,
            inspection_count: Mutex::new(0),
            pczt,
        }
    }

    fn tampered(pczt: TestPczt, tamper: Tamper) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            tamper,
            inspection_count: Mutex::new(0),
            pczt,
        }
    }

    fn calls(&self) -> Vec<CapturedCall> {
        self.calls.lock().expect("test mutex is healthy").clone()
    }

    fn inspection(&self, _pczt: &str, ordinal: usize) -> Value {
        let proved = ordinal > 0;
        let ironwood_amount =
            if ordinal == 0 && matches!(self.tamper, Tamper::FirstInspectionAmount) {
                PAYOUT_ZAT + 1
            } else {
                PAYOUT_ZAT
            };
        let ironwood_address =
            if ordinal == 0 && matches!(self.tamper, Tamper::FirstInspectionAddress) {
                test_ironwood_address(44)
            } else {
                self.pczt.recipient_unified_address.clone()
            };
        let transparent = self.pczt.recipient_kind == ReceiverKind::Transparent;
        let parsed = Pczt::parse(&BASE64_STANDARD.decode(&self.pczt.created).unwrap()).unwrap();
        let action_count = parsed.ironwood().actions().len();
        let mut ironwood_outputs = Vec::new();
        if let Some(extra) = self.pczt.extra_recipient.as_ref() {
            // Report the reverse of request order, as a shuffled action set may do.
            let extra = if matches!(self.tamper, Tamper::DuplicateInspectionRecipient) {
                &self.pczt.recipient_unified_address
            } else {
                extra
            };
            ironwood_outputs.push(json!({"value_zat": PAYOUT_ZAT, "user_address": extra}));
        }
        if !transparent {
            ironwood_outputs
                .push(json!({"value_zat": ironwood_amount, "user_address": ironwood_address}));
        }
        ironwood_outputs.resize(action_count, json!({"value_zat": 0, "user_address": null}));
        let mut inspection = json!({
            "tx_version": 6,
            "consensus_branch_id": "37a5165b",
            "expiry_height": EXPIRY_HEIGHT,
            "privacy_policy": self.privacy_policy(),
            "signing_hints": {
                "seed_fingerprint": self.pczt.source_seed_fingerprint.to_string(),
                "account_index": 0
            },
            "wallet_created": true,
            "fee_zat": self.pczt.fee_zat,
            "transparent": {
                "inputs": [],
                "outputs": []
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
                "actions": action_count,
                "signed_actions": action_count.saturating_sub(usize::from(ordinal <= 1)),
                "outputs": ironwood_outputs,
                "value_balance_zat": self.pczt.fee_zat,
                "proof_complete": proved
            }
        });
        if transparent {
            inspection["transparent"]["outputs"] = json!([{
                "value_zat": ironwood_amount,
                "address": self.pczt.recipient_unified_address,
                "user_address": ironwood_address
            }]);
            inspection["ironwood"]["value_balance_zat"] = json!(PAYOUT_ZAT + self.pczt.fee_zat);
        }
        inspection
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
            "getwalletstatus" => Ok(healthy_status()),
            "z_getaccount" => Ok(healthy_account(call.params()[0].clone(), &self.pczt)),
            "z_getbalances" => {
                let account_uuid = self
                    .calls
                    .lock()
                    .expect("test mutex is healthy")
                    .iter()
                    .rev()
                    .find(|captured| captured.method == "z_getaccount")
                    .expect("balance follows account lookup")
                    .params[0]
                    .clone();
                Ok(healthy_balances(account_uuid))
            }
            "z_exportviewingkey" => Ok(json!(self.pczt.source_ufvk)),
            "pczt_create" => Ok(json!({
                "pczt": match self.tamper {
                    Tamper::EmptyCreatedEffects => &self.pczt.empty,
                    Tamper::CreatedRecipientEffects => &self.pczt.altered_recipient,
                    Tamper::CreatedValueEffects => &self.pczt.altered_value,
                    Tamper::MainnetCoinType => &self.pczt.wrong_coin_type,
                    _ => &self.pczt.created,
                },
                "privacy_policy": if matches!(self.tamper, Tamper::WeakPrivacyPolicy) { "NoPrivacy" } else { self.privacy_policy() }
            })),
            "pczt_inspect" => {
                let pczt = call.params()[0].as_str().expect("PCZT string");
                let mut count = self.inspection_count.lock().expect("test mutex is healthy");
                let result = self.inspection(pczt, *count);
                *count += 1;
                Ok(result)
            }
            "pczt_prove" => Ok(json!({
                "pczt": if matches!(self.tamper, Tamper::ProvedEffects) {
                    &self.pczt.altered
                } else {
                    &self.pczt.proved
                },
                "sapling_proven": false,
                "orchard_proven": false,
                "ironwood_proven": true
            })),
            "pczt_sign" => Ok(json!({
                "pczt": match self.tamper {
                    Tamper::SignedEffects => &self.pczt.altered,
                    Tamper::MissingSignedAuthorization => &self.pczt.proved,
                    _ => &self.pczt.signed,
                },
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
                "hex": if matches!(self.tamper, Tamper::ExtractedEffects) {
                    &self.pczt.altered_raw_transaction
                } else {
                    &self.pczt.raw_transaction
                },
                "txid": if matches!(self.tamper, Tamper::ExtractedEffects) {
                    &self.pczt.altered_transaction_id
                } else {
                    &self.pczt.transaction_id
                },
                "stored": true
            })),
            method => panic!("unexpected wallet method {method}"),
        }
    }
}

struct ReadinessZallet {
    status: Value,
    account: Value,
    balances: Value,
    ufvk: String,
}

impl JsonRpcTransport for ReadinessZallet {
    fn call(&self, call: RpcCall) -> Result<Value, RpcTransportError> {
        match call.method() {
            "getwalletstatus" => Ok(self.status.clone()),
            "z_getaccount" => Ok(self.account.clone()),
            "z_getbalances" => Ok(self.balances.clone()),
            "z_exportviewingkey" => Ok(json!(self.ufvk)),
            method => panic!("unexpected readiness method {method}"),
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
            ZebraStep::Accepted => {
                let raw = hex::decode(call.params()[0].as_str().unwrap()).unwrap();
                let transaction =
                    Transaction::read(raw.as_slice(), zcash_protocol::consensus::BranchId::Nu6_3)
                        .expect("submitted fixture transaction parses");
                Ok(Value::String(transaction.txid().to_string()))
            }
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

fn fixture(root: &TestDirectory) -> (ZecSignerConfig, ZecPayoutRequest, TestPczt) {
    fixture_for(root, test_pczt())
}

fn fixture_for(
    root: &TestDirectory,
    pczt: TestPczt,
) -> (ZecSignerConfig, ZecPayoutRequest, TestPczt) {
    let account = Uuid::new_v4();
    let config_path = write_wallet_config(root.path(), None);
    let config = ZecSignerConfig::new(
        root.path().join("journal"),
        config_path,
        account,
        wcash_zec_payout_signer::parent_payout_address_commitment(&pczt.source_unified_address),
    )
    .expect("valid test signer configuration");
    let mut request = ZecPayoutRequest {
        batch: PayoutBatchRequest {
            batch_id: Uuid::new_v4(),
            asset: Asset::Zec,
            network: ChainNetwork::Testnet,
            ledger_root: [5; 32],
            reconciliation_id: Uuid::new_v4(),
            maximum_network_fee_zat: 1_000_000,
            outputs: vec![PayoutOutput {
                allocation_id: Uuid::new_v4(),
                canonical_address: pczt.recipient_unified_address.clone(),
                receiver_kind: pczt.recipient_kind,
                amount_zat: PAYOUT_ZAT,
            }],
        },
        source_account: account,
        fund_source: ZecFundSource::Orchard,
    };
    if let Some(extra) = pczt.extra_recipient.as_ref() {
        request.batch.outputs.push(PayoutOutput {
            allocation_id: Uuid::new_v4(),
            canonical_address: extra.clone(),
            receiver_kind: ReceiverKind::Ironwood,
            amount_zat: PAYOUT_ZAT,
        });
    }
    (config, request, pczt)
}

#[test]
fn beta_three_rpc_pipeline_is_exact_and_replay_is_side_effect_free() {
    let root = TestDirectory::new();
    let (config, request, pczt) = fixture(&root);
    let zallet = Arc::new(HappyZallet::new(pczt.clone()));
    let zebra = Arc::new(ScriptedZebra::new([ZebraStep::Accepted]));
    let signer =
        ZecPcztSigner::new(config, zallet.clone(), zebra.clone()).expect("safe signer can start");

    signer.readiness().expect("wallet is ready");
    let receipt = signer.execute(&request).expect("payout succeeds");
    assert_eq!(receipt.batch_id, request.batch.batch_id);
    assert_eq!(receipt.transaction_id, pczt.transaction_id);
    assert_eq!(receipt.output_total_zat, PAYOUT_ZAT);
    assert_eq!(
        receipt.unsigned_digest,
        expected_effects_digest(&pczt.created)
    );
    assert_ne!(
        receipt.unsigned_digest,
        request.batch.commitment().unwrap(),
        "the consensus transaction-effects digest is not an accounting commitment"
    );
    assert_eq!(
        receipt.transaction_id_bytes.as_slice(),
        hex::decode(&pczt.transaction_id).unwrap()
    );
    assert_eq!(
        receipt.signed_transaction,
        hex::decode(&pczt.raw_transaction).unwrap()
    );
    assert_eq!(receipt.network_fee_zat, 10_000);

    let call_count = zallet.calls().len() + zebra.calls().len();
    assert_eq!(signer.execute(&request).expect("exact replay"), receipt);
    assert_eq!(zallet.calls().len() + zebra.calls().len(), call_count);

    let calls = zallet.calls();
    assert_eq!(
        calls.iter().map(|call| call.method).collect::<Vec<_>>(),
        vec![
            "getwalletstatus",
            "z_getaccount",
            "z_getbalances",
            "z_exportviewingkey",
            "pczt_create",
            "getwalletstatus",
            "z_getaccount",
            "z_getbalances",
            "z_exportviewingkey",
            "pczt_inspect",
            "pczt_prove",
            "pczt_inspect",
            "pczt_sign",
            "pczt_inspect",
            "pczt_extract"
        ]
    );
    assert_eq!(calls[1].params, json!([request.source_account.to_string()]));
    assert_eq!(calls[2].params, json!([100]));
    assert_eq!(calls[3].params, json!([pczt.source_unified_address, false]));
    assert_eq!(calls[4].params[0], request.source_account.to_string());
    assert_eq!(
        calls[4].params[1][0]["address"],
        pczt.recipient_unified_address
    );
    assert_eq!(calls[4].params[1][0]["amount"].to_string(), "2.00000000");
    assert_eq!(calls[4].params[2], 100);
    assert_eq!(calls[4].params[3], "FullPrivacy");
    assert_eq!(calls[4].params[4], "orchard");
    assert_eq!(calls[12].params, json!([pczt.proved, "FullPrivacy", true]));
    assert!(calls[10].timeout_millis > calls[4].timeout_millis);
    assert!(calls.iter().all(|call| call.max_response_bytes > 0));
    assert_eq!(zebra.calls()[0].params, json!([pczt.raw_transaction]));
}

#[test]
fn transparent_p2pkh_and_p2sh_payouts_verify_real_effects_and_replay_exactly() {
    for script_hash in [false, true] {
        let root = TestDirectory::new();
        let (config, request, pczt) = fixture_for(&root, transparent_test_pczt(script_hash));
        let zallet = Arc::new(HappyZallet::new(pczt.clone()));
        let zebra = Arc::new(ScriptedZebra::new([ZebraStep::Accepted]));
        let signer = ZecPcztSigner::new(config, zallet.clone(), zebra.clone()).unwrap();
        let receipt = signer
            .execute(&request)
            .expect("transparent payout succeeds");
        assert_eq!(receipt.transaction_id, pczt.transaction_id);
        assert_eq!(receipt.output_total_zat, PAYOUT_ZAT);
        assert_eq!(receipt.network_fee_zat, pczt.fee_zat);
        let calls = zallet.calls();
        let create = calls
            .iter()
            .find(|call| call.method == "pczt_create")
            .unwrap();
        assert_eq!(create.params[3], "AllowRevealedRecipients");
        let sign = calls
            .iter()
            .find(|call| call.method == "pczt_sign")
            .unwrap();
        assert_eq!(sign.params[1], "AllowRevealedRecipients");
        let call_count = calls.len() + zebra.calls().len();
        assert_eq!(signer.execute(&request).unwrap(), receipt);
        assert_eq!(zallet.calls().len() + zebra.calls().len(), call_count);
    }
}

#[test]
fn transparent_script_substitution_is_rejected_even_when_wallet_echoes_requested_address() {
    let root = TestDirectory::new();
    let mut pczt = transparent_test_pczt(false);
    let requested_address = pczt.recipient_unified_address.clone();
    let (substituted, _) = build_destination_pczt(
        EXPIRY_HEIGHT,
        &RECIPIENT_SEED,
        PAYOUT_ZAT,
        Some(TransparentAddress::PublicKeyHash([0x55; 20])),
    );
    let parsed = Pczt::parse(&BASE64_STANDARD.decode(substituted).unwrap()).unwrap();
    let substituted = Updater::new(parsed)
        .update_transparent_with(|mut bundle| {
            bundle.update_output_with(0, |mut output| {
                output.set_user_address(requested_address);
                Ok(())
            })
        })
        .unwrap()
        .finish();
    pczt.created = BASE64_STANDARD.encode(substituted.serialize().unwrap());
    let (config, request, pczt) = fixture_for(&root, pczt);
    let zallet = Arc::new(HappyZallet::new(pczt));
    let zebra = Arc::new(ScriptedZebra::new([]));
    let signer = ZecPcztSigner::new(config, zallet.clone(), zebra.clone()).unwrap();
    assert_eq!(
        signer.execute(&request),
        Err(ZecPayoutError::WalletProtocolViolation)
    );
    assert!(!zallet
        .calls()
        .iter()
        .any(|call| matches!(call.method, "pczt_prove" | "pczt_sign")));
    assert!(zebra.calls().is_empty());
}

#[test]
fn weak_wallet_privacy_response_is_rejected_before_proving_or_signing() {
    for pczt in [test_pczt(), transparent_test_pczt(false)] {
        let root = TestDirectory::new();
        let (config, request, pczt) = fixture_for(&root, pczt);
        let zallet = Arc::new(HappyZallet::tampered(pczt, Tamper::WeakPrivacyPolicy));
        let zebra = Arc::new(ScriptedZebra::new([]));
        let signer = ZecPcztSigner::new(config, zallet.clone(), zebra.clone()).unwrap();
        assert_eq!(
            signer.execute(&request),
            Err(ZecPayoutError::WalletProtocolViolation)
        );
        assert!(!zallet
            .calls()
            .iter()
            .any(|call| matches!(call.method, "pczt_prove" | "pczt_sign")));
        assert!(zebra.calls().is_empty());
    }
}

#[test]
fn multiple_shielded_recipients_allow_shuffled_actions_but_reject_duplicate_recipients() {
    for tamper in [Tamper::None, Tamper::DuplicateInspectionRecipient] {
        let root = TestDirectory::new();
        let (config, request, pczt) = fixture_for(&root, multiple_recipient_pczt());
        let zallet = Arc::new(HappyZallet::tampered(pczt, tamper));
        let zebra = Arc::new(ScriptedZebra::new([ZebraStep::Accepted]));
        let signer = ZecPcztSigner::new(config, zallet.clone(), zebra.clone()).unwrap();
        let result = signer.execute(&request);
        if matches!(tamper, Tamper::None) {
            let receipt = result.expect("valid shuffled multi-recipient payout");
            assert_eq!(receipt.output_total_zat, 2 * PAYOUT_ZAT);
            assert_eq!(receipt.network_fee_zat, FEE_ZAT);
        } else {
            assert_eq!(result, Err(ZecPayoutError::WalletProtocolViolation));
            assert!(!zallet
                .calls()
                .iter()
                .any(|call| call.method == "pczt_prove"));
            assert!(zebra.calls().is_empty());
        }
    }
}

#[test]
fn mixed_transparent_and_shielded_batch_preserves_every_recipient() {
    let root = TestDirectory::new();
    let (config, request, pczt) = fixture_for(&root, mixed_recipient_pczt());
    let zallet = Arc::new(HappyZallet::new(pczt));
    let zebra = Arc::new(ScriptedZebra::new([ZebraStep::Accepted]));
    let signer = ZecPcztSigner::new(config, zallet.clone(), zebra).unwrap();
    let receipt = signer
        .execute(&request)
        .expect("both recipient types are paid from shielded funds");
    assert_eq!(receipt.output_total_zat, 2 * PAYOUT_ZAT);
    assert_eq!(receipt.network_fee_zat, FEE_ZAT);
    assert_eq!(
        zallet
            .calls()
            .iter()
            .find(|call| call.method == "pczt_create")
            .unwrap()
            .params[3],
        "AllowRevealedRecipients"
    );
}

#[cfg(feature = "regtest")]
#[test]
fn regtest_wallet_profile_cannot_cross_testnet_batch_or_address_boundaries() {
    let root = TestDirectory::new();
    let (config, mut request, pczt) = fixture(&root);
    let config_path = root.path().join("zallet.toml");
    let contents = fs::read_to_string(&config_path)
        .unwrap()
        .replace("network = \"test\"", "network = \"regtest\"");
    fs::write(&config_path, contents).unwrap();
    assert_eq!(
        validate_zallet_configuration(&config_path),
        Err(ZecPayoutError::UnsafeWalletConfiguration)
    );
    wcash_zec_payout_signer::validate_zallet_regtest_configuration(&config_path).unwrap();
    let zallet = Arc::new(HappyZallet::new(pczt));
    let zebra = Arc::new(ScriptedZebra::new([]));
    assert!(matches!(
        ZecPcztSigner::new(config.clone(), zallet.clone(), zebra.clone()),
        Err(ZecPayoutError::UnsafeWalletConfiguration)
    ));
    let signer = ZecPcztSigner::new(
        config.with_regtest_network().unwrap(),
        zallet.clone(),
        zebra,
    )
    .unwrap();
    assert_eq!(signer.prepare(&request), Err(ZecPayoutError::WrongNetwork));
    request.batch.network = ChainNetwork::Regtest;
    assert_eq!(
        signer.prepare(&request),
        Err(ZecPayoutError::InvalidRequest)
    );
    assert!(zallet.calls().is_empty());
}

#[test]
fn prepare_and_recovery_never_submit_to_zebra() {
    let root = TestDirectory::new();
    let (config, request, pczt) = fixture(&root);
    let zallet = Arc::new(HappyZallet::new(pczt.clone()));
    let zebra = Arc::new(ScriptedZebra::new([]));
    let signer = ZecPcztSigner::new(config.clone(), zallet.clone(), zebra.clone())
        .expect("safe signer can start");
    let prepared = signer.prepare(&request).expect("PCZT is prepared");
    assert_eq!(prepared.transaction_id, pczt.transaction_id);
    assert!(zebra.calls().is_empty(), "prepare must not broadcast");

    let wallet_calls = zallet.calls().len();
    let recovered = ZecPcztSigner::new(config, zallet.clone(), zebra.clone())
        .expect("signer restarts")
        .recover_prepared(&request)
        .expect("journal recovery succeeds")
        .expect("prepared artifact exists");
    assert_eq!(recovered.payout, prepared);
    assert_eq!(zallet.calls().len(), wallet_calls);
    assert!(zebra.calls().is_empty(), "recovery must not broadcast");
}

#[test]
fn extracted_checkpoint_recovers_identical_bytes_without_resigning() {
    let root = TestDirectory::new();
    let (config, request, pczt) = fixture(&root);
    let zallet = Arc::new(HappyZallet::new(pczt.clone()));
    let zebra = Arc::new(ScriptedZebra::new([]));
    let interrupted = ZecPcztSigner::new(config.clone(), zallet.clone(), zebra.clone())
        .expect("safe signer can start")
        .with_checkpoint_hook(Arc::new(InterruptOnce {
            target: Checkpoint::StagePersisted(PipelineStage::Extracted),
            fired: AtomicBool::new(false),
        }));
    assert_eq!(
        interrupted.prepare(&request),
        Err(ZecPayoutError::Interrupted)
    );
    let wallet_calls = zallet.calls().len();
    let recovered = ZecPcztSigner::new(config, zallet.clone(), zebra.clone())
        .expect("signer restarts")
        .recover_prepared(&request)
        .expect("journal recovery succeeds")
        .expect("extracted bytes were durable");
    assert_eq!(recovered.payout.transaction_id, pczt.transaction_id);
    assert_eq!(
        zallet.calls().len(),
        wallet_calls,
        "recovery cannot re-sign"
    );
    assert!(zebra.calls().is_empty());
}

#[test]
fn unresolved_and_completed_journals_recover_without_new_node_calls() {
    for step in [ZebraStep::Timeout, ZebraStep::Accepted] {
        let root = TestDirectory::new();
        let (config, request, pczt) = fixture(&root);
        let zallet = Arc::new(HappyZallet::new(pczt.clone()));
        let zebra = Arc::new(ScriptedZebra::new([step]));
        let signer = ZecPcztSigner::new(config.clone(), zallet.clone(), zebra.clone())
            .expect("safe signer can start");
        let _result = signer.execute(&request);
        let node_calls = zebra.calls().len();
        let recovered = ZecPcztSigner::new(config, zallet, zebra.clone())
            .expect("signer restarts")
            .recover_prepared(&request)
            .expect("journal recovery succeeds")
            .expect("exact artifact remains recoverable");
        assert_eq!(recovered.payout.transaction_id, pczt.transaction_id);
        assert_eq!(zebra.calls().len(), node_calls);
    }
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
        let (config, request, pczt) = fixture(&root);
        let zallet = Arc::new(HappyZallet::new(pczt));
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
            test_pczt().transaction_id,
            "checkpoint {checkpoint:?}"
        );
        let broadcast_calls = zebra.calls();
        assert!(
            broadcast_calls
                .iter()
                .all(|call| call.params == json!([test_pczt().raw_transaction])),
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
        let (config, request, pczt) = fixture(&root);
        let zallet = Arc::new(HappyZallet::tampered(pczt, tamper));
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
fn claimed_outputs_cannot_hide_an_empty_created_pczt() {
    let root = TestDirectory::new();
    let (config, request, pczt) = fixture(&root);
    let zallet = Arc::new(HappyZallet::tampered(pczt, Tamper::EmptyCreatedEffects));
    let signer = ZecPcztSigner::new(config, zallet.clone(), Arc::new(ScriptedZebra::new([])))
        .expect("safe signer can start");

    assert_eq!(
        signer.execute(&request),
        Err(ZecPayoutError::WalletProtocolViolation)
    );
    let calls = zallet.calls();
    assert!(calls.iter().any(|call| call.method == "pczt_create"));
    assert!(
        !calls
            .iter()
            .any(|call| matches!(call.method, "pczt_inspect" | "pczt_prove" | "pczt_sign")),
        "the parsed Created PCZT must fail before creator-claimed inspection or signing"
    );
}

#[test]
fn claimed_outputs_cannot_hide_changed_created_recipient_or_value() {
    for tamper in [Tamper::CreatedRecipientEffects, Tamper::CreatedValueEffects] {
        let root = TestDirectory::new();
        let (config, request, pczt) = fixture(&root);
        let zallet = Arc::new(HappyZallet::tampered(pczt, tamper));
        let signer = ZecPcztSigner::new(config, zallet.clone(), Arc::new(ScriptedZebra::new([])))
            .expect("safe signer can start");

        assert_eq!(
            signer.execute(&request),
            Err(ZecPayoutError::WalletProtocolViolation)
        );
        let calls = zallet.calls();
        assert!(calls.iter().any(|call| call.method == "pczt_create"));
        assert!(
            !calls.iter().any(|call| call.method == "pczt_inspect"),
            "parsed transaction effects must fail before creator-claimed inspection"
        );
    }
}

#[test]
fn testnet_coin_type_one_is_required_in_the_created_pczt() {
    let valid_root = TestDirectory::new();
    let (valid_config, valid_request, valid_pczt) = fixture(&valid_root);
    let valid_signer = ZecPcztSigner::new(
        valid_config,
        Arc::new(HappyZallet::new(valid_pczt)),
        Arc::new(ScriptedZebra::new([ZebraStep::Accepted])),
    )
    .expect("safe signer can start");
    valid_signer
        .execute(&valid_request)
        .expect("authoritative Zcash Testnet coin type 1 is accepted");

    let root = TestDirectory::new();
    let (config, request, pczt) = fixture(&root);
    let zallet = Arc::new(HappyZallet::tampered(pczt, Tamper::MainnetCoinType));
    let signer = ZecPcztSigner::new(config, zallet.clone(), Arc::new(ScriptedZebra::new([])))
        .expect("safe signer can start");

    assert_eq!(
        signer.execute(&request),
        Err(ZecPayoutError::WalletProtocolViolation)
    );
    assert!(
        !zallet
            .calls()
            .iter()
            .any(|call| call.method == "pczt_inspect"),
        "SLIP-44 133 is mainnet; Zcash Testnet PCZTs must carry coin type 1"
    );
}

#[test]
fn extracted_transaction_must_match_the_approved_pczt_effects() {
    let root = TestDirectory::new();
    let (config, request, pczt) = fixture(&root);
    let zallet = Arc::new(HappyZallet::tampered(pczt, Tamper::ExtractedEffects));
    let zebra = Arc::new(ScriptedZebra::new([]));
    let signer =
        ZecPcztSigner::new(config, zallet.clone(), zebra.clone()).expect("safe signer can start");

    assert_eq!(
        signer.execute(&request),
        Err(ZecPayoutError::WalletProtocolViolation)
    );
    assert!(zallet
        .calls()
        .iter()
        .any(|call| call.method == "pczt_extract"));
    assert!(
        zebra.calls().is_empty(),
        "substituted extraction bytes must never reach broadcast"
    );
}

#[test]
fn signed_pczt_must_be_locally_extractable_before_zallet_extracts_it() {
    let root = TestDirectory::new();
    let (config, request, pczt) = fixture(&root);
    let zallet = Arc::new(HappyZallet::tampered(
        pczt,
        Tamper::MissingSignedAuthorization,
    ));
    let signer = ZecPcztSigner::new(config, zallet.clone(), Arc::new(ScriptedZebra::new([])))
        .expect("safe signer can start");

    assert_eq!(
        signer.execute(&request),
        Err(ZecPayoutError::WalletProtocolViolation)
    );
    assert!(
        !zallet
            .calls()
            .iter()
            .any(|call| call.method == "pczt_extract"),
        "missing spend authorization must fail the local extractor before wallet storage"
    );
}

#[test]
fn network_asset_account_and_fund_source_are_independently_fenced() {
    let root = TestDirectory::new();
    let (config, request, pczt) = fixture(&root);
    let zallet = Arc::new(HappyZallet::new(pczt));
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
    let (config, request, pczt) = fixture(&root);
    let zallet = Arc::new(HappyZallet::new(pczt));
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
fn legacy_journal_without_consensus_effects_digest_fails_closed() {
    let root = TestDirectory::new();
    let (config, request, pczt) = fixture(&root);
    let journal_directory = root.path().join("journal");
    fs::create_dir(&journal_directory).expect("journal directory");
    let record_path = journal_directory.join(format!("{}.json", request.batch.batch_id.simple()));
    fs::write(
        &record_path,
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "record": {
                "batch_id": request.batch.batch_id,
                "pipeline_commitment": vec![1; 32],
                "portal_commitment": vec![2; 32],
                "output_total_zat": PAYOUT_ZAT,
                "stage": {"stage": "reserved"}
            },
            "checksum": "00".repeat(32)
        }))
        .expect("legacy fixture serializes"),
    )
    .expect("legacy fixture is written");
    #[cfg(unix)]
    fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600))
        .expect("journal fixture permissions");

    let zallet = Arc::new(HappyZallet::new(pczt));
    let signer = ZecPcztSigner::new(config, zallet.clone(), Arc::new(ScriptedZebra::new([])))
        .expect("signer opens journal directory");
    assert_eq!(
        signer.execute(&request),
        Err(ZecPayoutError::JournalCorrupt)
    );
    assert!(zallet.calls().is_empty());
}

#[test]
fn timeout_retries_identical_bytes_and_already_known_resolves_success() {
    let root = TestDirectory::new();
    let (config, request, pczt) = fixture(&root);
    let zallet = Arc::new(HappyZallet::new(pczt));
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
        test_pczt().transaction_id
    );
    let calls = zebra.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].params, calls[1].params);
}

#[test]
fn explicit_rejection_is_terminal_and_wrong_txid_is_ambiguous() {
    let root = TestDirectory::new();
    let (config, request, pczt) = fixture(&root);
    let zallet = Arc::new(HappyZallet::new(pczt));
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
    let (config, request, pczt) = fixture(&second_root);
    let zallet = Arc::new(HappyZallet::new(pczt));
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
fn prove_or_sign_cannot_change_consensus_transaction_effects() {
    for tamper in [Tamper::ProvedEffects, Tamper::SignedEffects] {
        let root = TestDirectory::new();
        let (config, request, pczt) = fixture(&root);
        let zallet = Arc::new(HappyZallet::tampered(pczt, tamper));
        let zebra = Arc::new(ScriptedZebra::new([]));
        let signer =
            ZecPcztSigner::new(config, zallet, zebra.clone()).expect("safe signer can start");

        assert_eq!(
            signer.execute(&request),
            Err(ZecPayoutError::WalletProtocolViolation)
        );
        assert!(zebra.calls().is_empty());
    }
}

#[test]
fn consensus_effects_digest_survives_real_proof_and_signature_but_not_effect_changes() {
    let pczt = test_pczt();

    let expected = expected_effects_digest(&pczt.created);
    assert_eq!(expected_effects_digest(&pczt.proved), expected);
    assert_eq!(expected_effects_digest(&pczt.signed), expected);
    assert_ne!(expected_effects_digest(&pczt.altered), expected);
}

#[test]
fn readiness_rejects_incomplete_sync_and_ambiguous_account_identity() {
    let root = TestDirectory::new();
    let (config, request, pczt) = fixture(&root);
    let valid_account = healthy_account(json!(request.source_account.to_string()), &pczt);
    let valid_balances = healthy_balances(json!(request.source_account.to_string()));

    let mut missing_wallet_tip = healthy_status();
    missing_wallet_tip
        .as_object_mut()
        .expect("status object")
        .remove("wallet_tip");
    let mut mismatched_tip = healthy_status();
    mismatched_tip["wallet_tip"]["blockhash"] = json!("22".repeat(32));
    let mut incomplete_height = healthy_status();
    incomplete_height["fully_synced_height"] = json!(EXPIRY_HEIGHT - 21);
    let mut missing_synced_height = healthy_status();
    missing_synced_height
        .as_object_mut()
        .expect("status object")
        .remove("fully_synced_height");
    let mut remaining_work = healthy_status();
    remaining_work["sync_work_remaining"] = json!({
        "unscanned_blocks": 1,
        "progress": {"numerator": 1, "denominator": 2}
    });
    let mut ambiguous_null_work = healthy_status();
    ambiguous_null_work["sync_work_remaining"] = Value::Null;
    let mut locked = healthy_status();
    locked["locked"] = json!(true);

    let invalid_statuses = [
        missing_wallet_tip,
        mismatched_tip,
        incomplete_height,
        missing_synced_height,
        remaining_work,
        ambiguous_null_work,
        locked,
    ];
    for status in invalid_statuses {
        let wallet = Arc::new(ReadinessZallet {
            status,
            account: valid_account.clone(),
            balances: valid_balances.clone(),
            ufvk: pczt.source_ufvk.clone(),
        });
        let signer = ZecPcztSigner::new(config.clone(), wallet, Arc::new(ScriptedZebra::new([])))
            .expect("static signer policy is valid");
        assert!(signer.readiness().is_err());
    }

    let mut wrong_account = valid_account.clone();
    wrong_account["account_uuid"] = json!(Uuid::new_v4().to_string());
    let mut missing_seed = valid_account.clone();
    missing_seed
        .as_object_mut()
        .expect("account object")
        .remove("seedfp");
    let mut missing_account_index = valid_account.clone();
    missing_account_index
        .as_object_mut()
        .expect("account object")
        .remove("zip32_account_index");
    let mut no_addresses = valid_account.clone();
    no_addresses["addresses"] = json!([]);
    let mut nonmatching_address = valid_account.clone();
    nonmatching_address["addresses"][0]["ua"] = json!(test_ironwood_address(0x5a));
    let mut duplicate_matching_address = valid_account;
    let duplicate = duplicate_matching_address["addresses"][0].clone();
    duplicate_matching_address["addresses"]
        .as_array_mut()
        .expect("addresses array")
        .push(duplicate);
    for account in [
        wrong_account,
        missing_seed,
        missing_account_index,
        no_addresses,
        nonmatching_address,
        duplicate_matching_address,
    ] {
        let wallet = Arc::new(ReadinessZallet {
            status: healthy_status(),
            account,
            balances: valid_balances.clone(),
            ufvk: pczt.source_ufvk.clone(),
        });
        let signer = ZecPcztSigner::new(config.clone(), wallet, Arc::new(ScriptedZebra::new([])))
            .expect("static signer policy is valid");
        assert_eq!(
            signer.readiness(),
            Err(ZecPayoutError::WalletProtocolViolation)
        );
    }

    let mut legacy_orchard_balance = valid_balances;
    legacy_orchard_balance["accounts"][0]["orchard"] = json!({
        "spendable": {"valueZat": 1}
    });
    let wallet = Arc::new(ReadinessZallet {
        status: healthy_status(),
        account: healthy_account(json!(request.source_account.to_string()), &pczt),
        balances: legacy_orchard_balance,
        ufvk: pczt.source_ufvk,
    });
    let signer = ZecPcztSigner::new(config, wallet, Arc::new(ScriptedZebra::new([])))
        .expect("static signer policy is valid");
    assert_eq!(
        signer.readiness(),
        Err(ZecPayoutError::WalletProtocolViolation)
    );
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

#[test]
fn parent_payout_commitment_is_domain_separated_and_required() {
    assert_eq!(
        hex::encode(wcash_zec_payout_signer::parent_payout_address_commitment(
            "u1test-address"
        )),
        "7216074cdd20dba22c98f155b7cad07883de0a79b62d6584170948014695e427"
    );

    let root = TestDirectory::new();
    let config_path = write_wallet_config(root.path(), None);
    assert_eq!(
        ZecSignerConfig::new(
            root.path().join("journal"),
            config_path,
            Uuid::new_v4(),
            [0; 32],
        ),
        Err(ZecPayoutError::InvalidRequest)
    );
}
