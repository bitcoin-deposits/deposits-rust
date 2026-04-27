//! Schema validation: .ksy documentation → TLV bytes → Rust decode → re-encode → compare
//!
//! This test mechanically constructs TLV payloads from the field type reference
//! documented in deposits_protocol.ksy, then verifies the Rust codec can parse
//! and re-serialize them byte-for-byte. This ensures the .ksy documentation and
//! the Rust implementation agree on the wire format.
//!
//! If a field is added to Rust but not documented in .ksy (or vice versa),
//! the roundtrip will fail because the Rust codec will produce different bytes.

use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::tlv::{write_varint, TlvDecode, TlvEncode, TlvStream};
use deposits_protocol::types::{FeeStructure, TransferFeeSchedule};

// ============================================================================
// Test value generators (deterministic)
// ============================================================================

fn pubkey_bytes() -> Vec<u8> {
    // Valid compressed secp256k1 pubkey (generator point)
    hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap()
}

fn hash32() -> Vec<u8> {
    vec![0xab; 32]
}
fn hash20() -> Vec<u8> {
    vec![0xcd; 20]
}
fn sig64() -> Vec<u8> {
    vec![0x30; 64]
}
fn deposit_id() -> Vec<u8> {
    vec![0x01; 16]
}
fn str_bytes(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}
fn u8_bytes(v: u8) -> Vec<u8> {
    vec![v]
}
fn u16_bytes(v: u16) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}
fn u32_bytes(v: u32) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}
fn u64_bytes(v: u64) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

fn fee_structure_tlv() -> Vec<u8> {
    // Nested TLV matching FeeStructure: type 0 = annualized_msats, 2 = annualized_bps, 4 = frequency
    let fees = FeeStructure {
        annualized_msats: 1000,
        annualized_bps: 50,
        frequency_blocks: 2016,
    };
    fees.tlv_encode()
}

fn transfer_fee_tlv() -> Vec<u8> {
    let tf = TransferFeeSchedule {
        fixed_msats: 2,
        rate_bps: 20,
    };
    tf.tlv_encode()
}

fn witness_tlv() -> Vec<u8> {
    // Witness encoding: varint(count) || (varint(len) || element)*
    let mut buf = Vec::new();
    write_varint(&mut buf, 1).unwrap(); // 1 stack element
    write_varint(&mut buf, 64).unwrap(); // 64 bytes
    buf.extend_from_slice(&[0x30; 64]);
    buf
}

// ============================================================================
// Schema: each entry maps a discriminant to its required TLV fields
// from the .ksy documentation. Fields are (type_number, value_bytes).
// ============================================================================

/// Build a TLV payload from a discriminant and list of (field_type, value) pairs.
/// Fields are inserted into a TlvStream (BTreeMap ensures canonical ordering).
fn build_tlv(disc: u8, fields: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut stream = TlvStream::new();
    stream.insert(0, vec![disc]); // discriminant always at type 0
    for (ft, val) in fields {
        stream.insert(*ft, val.clone());
    }
    stream.encode()
}

/// Verify: build from .ksy schema → Rust decode → re-encode → bytes match
fn validate_schema(disc: u8, name: &str, fields: &[(u64, Vec<u8>)]) {
    let ksy_bytes = build_tlv(disc, fields);

    // Rust decode
    let decoded = LedgerOperation::tlv_decode(&ksy_bytes).unwrap_or_else(|e| {
        panic!(
            "[{}] disc={}: Rust decode failed on .ksy-derived payload: {:?}",
            name, disc, e
        )
    });

    assert_eq!(
        decoded.discriminant(),
        disc,
        "[{}]: decoded discriminant {} != expected {}",
        name,
        decoded.discriminant(),
        disc
    );

    // Re-encode
    let rust_bytes = decoded.tlv_encode();

    // Compare
    if rust_bytes != ksy_bytes {
        // Diff: find which fields differ
        let ksy_stream = TlvStream::decode(&ksy_bytes).unwrap();
        let rust_stream = TlvStream::decode(&rust_bytes).unwrap();

        let ksy_types: Vec<u64> = ksy_stream.iter().map(|(t, _)| t).collect();
        let rust_types: Vec<u64> = rust_stream.iter().map(|(t, _)| t).collect();

        // Fields in Rust but not in .ksy
        for t in &rust_types {
            if !ksy_types.contains(t) {
                panic!(
                    "[{}] disc={}: Rust emits field type {} not documented in .ksy",
                    name, disc, t
                );
            }
        }
        // Fields in .ksy but not in Rust
        for t in &ksy_types {
            if !rust_types.contains(t) {
                panic!(
                    "[{}] disc={}: .ksy documents field type {} but Rust doesn't emit it",
                    name, disc, t
                );
            }
        }
        // Value differences
        for (t, ksy_val) in ksy_stream.iter() {
            if let Some(rust_val) = rust_stream.get(t) {
                if ksy_val != rust_val {
                    panic!(
                        "[{}] disc={}: field {} values differ (ksy {} bytes, rust {} bytes)",
                        name,
                        disc,
                        t,
                        ksy_val.len(),
                        rust_val.len()
                    );
                }
            }
        }
        panic!(
            "[{}] disc={}: bytes differ but no field-level diff found",
            name, disc
        );
    }
}

// ============================================================================
// Per-operation schema tests (field types from .ksy TLV field reference)
// ============================================================================

// Field type constants (from .ksy documentation)
const DISCRIMINANT: u64 = 0;
const AMOUNT: u64 = 2;
const NEW_AMOUNT: u64 = 8;
const PUBKEY: u64 = 10;
const FEES: u64 = 12;
const PAYMENT_HASH: u64 = 14;
const INVOICE: u64 = 16;
const COSIGNER_SIG: u64 = 18;
const NEW_FEES: u64 = 20;
const INVOICE_ID: u64 = 26;
const SEQUENCE_NUMBER: u64 = 28;
const PAYMENT_ID: u64 = 30;
const PREIMAGE: u64 = 34;
const BLOCK_HEIGHT: u64 = 36;
#[allow(dead_code)]
const COLLATERAL_OPERATOR: u64 = 38;
const LEDGER_HASH: u64 = 42;
const QUORUM_MEMBER: u64 = 44;
const QUORUM_MEMBER_SIG: u64 = 46;
const OPERATOR_SIG: u64 = 48;
const OPERATOR_ID: u64 = 56;
const RESERVES_ID: u64 = 58;
const ENFORCEMENT_BLOCK: u64 = 64;
const TXID: u64 = 66;
const VOUT: u64 = 68;
const DESTINATION_ADDRESS: u64 = 70;
const WITHDRAWAL_ID: u64 = 72;
const FUNDING_ADDRESS: u64 = 74;
#[allow(dead_code)]
const LOCK_UNTIL_BLOCK: u64 = 76;
const MEMBERSHIP_EXPIRES: u64 = 82;
const SPENDING_TXID: u64 = 90;
const NEW_OUTPOINT_TXID: u64 = 84;
const NEW_OUTPOINT_VOUT: u64 = 92;
const QUORUM_THRESHOLD: u64 = 93;
const QUORUM_SIZE: u64 = 94;
const QUORUM_EXPIRY: u64 = 86;
const GENESIS_BLOCK: u64 = 96;
const REASON: u64 = 100;
const LAST_VALID_SEQUENCE: u64 = 102;
const NEW_CUSTODIAN: u64 = 108;
const ARMED_BLOCK: u64 = 118;
const CLAIM_TXID: u64 = 110;
const NEW_RESERVES_ADDRESS: u64 = 120;
const COMMITMENT_HASH: u64 = 112;
const TARGET_RESERVES: u64 = 122;
const MEMBER_LEDGER_ID: u64 = 114;
#[allow(dead_code)]
const COLLATERAL_LEDGER_ID: u64 = 124;
const DEPOSIT_ID: u64 = 200;
const DESCRIPTOR: u64 = 202;
const WITNESS: u64 = 204;
const NEW_DESCRIPTOR: u64 = 208;
const NONCE: u64 = 210;
const SOURCE_DEPOSIT_ID: u64 = 212;
const DESTINATION_DEPOSIT_ID: u64 = 214;
const COMPLETION_SCRIPT: u64 = 216;
const TIMEOUT_HEIGHT: u64 = 218;
const TRANSFER_ID: u64 = 220;
const BLOCK_HASH: u64 = 222;
const SCRIPT_WITNESS: u64 = 224;
const TRANSFER_FEES: u64 = 226;
const FAIL_REASON: u64 = 228;
const MIN_FEE_BPS: u64 = 234;
const MIN_FEE_FIXED: u64 = 236;
const MAX_FEE_PERIOD: u64 = 238;
// 240 (was COLLATERAL_LOCK_AMOUNT) removed with collateral-in-UTXO migration
// 242 is still MEMBERSHIP_UNTIL on QuorumAddMember (see inline use below)
// Fee amount field
const FEE: u64 = 2; // shares with AMOUNT for some ops, but fee uses it differently in TransferLock

#[test]
fn schema_ledger_open() {
    validate_schema(
        1,
        "LedgerOpen",
        &[
            (OPERATOR_ID, pubkey_bytes()),
            (RESERVES_ID, str_bytes("bcrt1qtest")),
            (62, u64_bytes(100_000_000)), // RESERVES_AMOUNT
            (88, u64_bytes(0)),           // COLLATERAL_AMOUNT
            (GENESIS_BLOCK, u32_bytes(100)),
        ],
    );
}

#[test]
fn schema_quorum_begin() {
    validate_schema(
        12,
        "QuorumBegin",
        &[
            (RESERVES_ID, str_bytes("bcrt1qtest")),
            (SPENDING_TXID, hash32()),
            (NEW_OUTPOINT_TXID, hash32()),
            (NEW_OUTPOINT_VOUT, u32_bytes(0)),
            (AMOUNT, u64_bytes(100_000_000)),
            (QUORUM_EXPIRY, u32_bytes(1000)),
            (LEDGER_HASH, hash32()),
            (6, pubkey_bytes()),         // QUORUM_MEMBERS — one member
            (88, u64_bytes(50_000_000)), // TOTAL_COLLATERAL
        ],
    );
}

#[test]
fn schema_deposit_open() {
    validate_schema(
        20,
        "DepositOpen",
        &[
            (DEPOSIT_ID, deposit_id()),
            (DESCRIPTOR, str_bytes("pk(0279be66...)")),
            (FEES, fee_structure_tlv()),
            (TRANSFER_FEES, transfer_fee_tlv()),
            (PAYMENT_HASH, hash32()),
            (INVOICE, str_bytes("lnbcrt1test")),
            (COSIGNER_SIG, sig64()),
        ],
    );
}

#[test]
fn schema_deposit_close() {
    validate_schema(21, "DepositClose", &[(DEPOSIT_ID, deposit_id())]);
}

#[test]
fn schema_fee_change() {
    validate_schema(
        22,
        "FeeChange",
        &[
            (DEPOSIT_ID, deposit_id()),
            (NEW_FEES, fee_structure_tlv()),
            (250, u32_bytes(0)), // EFFECTIVE_BLOCK
        ],
    );
}

#[test]
fn schema_deposit_key_rotate() {
    validate_schema(
        23,
        "DepositKeyRotate",
        &[
            (DEPOSIT_ID, deposit_id()),
            (NEW_DESCRIPTOR, str_bytes("pk(03...)")),
            (WITNESS, witness_tlv()),
        ],
    );
}

#[test]
fn schema_invoice_credit() {
    validate_schema(
        30,
        "InvoiceCredit",
        &[
            (PAYMENT_HASH, hash32()),
            (DEPOSIT_ID, deposit_id()),
            (AMOUNT, u64_bytes(10_000_000)),
            (INVOICE_ID, str_bytes("bolt11:test")),
            (SEQUENCE_NUMBER, u64_bytes(42)),
        ],
    );
}

#[test]
fn schema_invoice_lock() {
    validate_schema(
        31,
        "InvoiceLock",
        &[
            (DEPOSIT_ID, deposit_id()),
            (AMOUNT, u64_bytes(5_000_000)),
            (PAYMENT_ID, hash32()),
            (SEQUENCE_NUMBER, u64_bytes(43)),
            (WITNESS, witness_tlv()),
        ],
    );
}

#[test]
fn schema_invoice_fail() {
    validate_schema(
        32,
        "InvoiceFail",
        &[
            (DEPOSIT_ID, deposit_id()),
            (AMOUNT, u64_bytes(5_000_000)),
            (PAYMENT_ID, hash32()),
            (SEQUENCE_NUMBER, u64_bytes(44)),
        ],
    );
}

#[test]
fn schema_invoice_fulfill() {
    validate_schema(
        33,
        "InvoiceFulfill",
        &[
            (DEPOSIT_ID, deposit_id()),
            (AMOUNT, u64_bytes(5_000_000)),
            (PAYMENT_ID, hash32()),
            (SEQUENCE_NUMBER, u64_bytes(45)),
            (WITNESS, witness_tlv()),
            (PREIMAGE, hash32()),
        ],
    );
}

#[test]
fn schema_onchain_credit() {
    validate_schema(
        35,
        "OnchainCredit",
        &[
            (TXID, hash32()),
            (VOUT, u32_bytes(0)),
            (DEPOSIT_ID, deposit_id()),
            (AMOUNT, u64_bytes(100_000_000)),
            (FUNDING_ADDRESS, str_bytes("bcrt1qfund")),
        ],
    );
}

#[test]
fn schema_onchain_lock() {
    validate_schema(
        36,
        "OnchainLock",
        &[
            (DEPOSIT_ID, deposit_id()),
            (AMOUNT, u64_bytes(50_000_000)),
            (FEES, u64_bytes(500)),
            (DESTINATION_ADDRESS, str_bytes("bcrt1qdest")),
            (WITHDRAWAL_ID, hash32()),
            (WITNESS, witness_tlv()),
        ],
    );
}

#[test]
fn schema_onchain_fail() {
    validate_schema(
        37,
        "OnchainFail",
        &[(DEPOSIT_ID, deposit_id()), (WITHDRAWAL_ID, hash32())],
    );
}

#[test]
fn schema_onchain_fulfill() {
    validate_schema(
        38,
        "OnchainFulfill",
        &[
            (DEPOSIT_ID, deposit_id()),
            (WITHDRAWAL_ID, hash32()),
            (AMOUNT, u64_bytes(50_000_000)),
            (TXID, hash32()),
            (DESTINATION_ADDRESS, str_bytes("bcrt1qdest")),
        ],
    );
}

#[test]
fn schema_quorum_add_member() {
    validate_schema(
        43,
        "QuorumAddMember",
        &[
            (QUORUM_MEMBER, pubkey_bytes()),
            (QUORUM_MEMBER_SIG, sig64()),
            (MEMBER_LEDGER_ID, str_bytes("abc123")),
            (MIN_FEE_BPS, u16_bytes(500)),
            (MIN_FEE_FIXED, u64_bytes(100_000)),
            (MAX_FEE_PERIOD, u32_bytes(2016)),
            (242, u32_bytes(10000)), // MEMBERSHIP_UNTIL
        ],
    );
}

#[test]
fn schema_quorum_remove_member() {
    validate_schema(
        44,
        "QuorumRemoveMember",
        &[(QUORUM_MEMBER, pubkey_bytes()), (OPERATOR_SIG, sig64())],
    );
}

#[test]
fn schema_quorum_join() {
    validate_schema(
        46,
        "QuorumJoin",
        &[
            (OPERATOR_ID, pubkey_bytes()),
            (RESERVES_ID, str_bytes("abc123def456")),
            (MEMBERSHIP_EXPIRES, u32_bytes(100_000)),
        ],
    );
}

#[test]
fn schema_fee_collect() {
    validate_schema(
        50,
        "FeeCollect",
        &[
            (DEPOSIT_ID, deposit_id()),
            (AMOUNT, u64_bytes(1000)),
            (BLOCK_HEIGHT, u32_bytes(500)),
        ],
    );
}

#[test]
fn schema_custody_dispute() {
    validate_schema(
        54,
        "DisputeEnter",
        &[
            (LAST_VALID_SEQUENCE, u64_bytes(10)),
            (REASON, str_bytes("hash_chain_broken")),
        ],
    );
}

#[test]
fn schema_custody_acquire() {
    validate_schema(
        55,
        "DisputeAcquire",
        &[
            (NEW_CUSTODIAN, pubkey_bytes()),
            (CLAIM_TXID, hash32()),
            (NEW_RESERVES_ADDRESS, str_bytes("bcrt1qnew")),
        ],
    );
}

#[test]
fn schema_custody_yield() {
    validate_schema(56, "DisputeYield", &[]);
}

#[test]
fn schema_custody_armed() {
    validate_schema(
        57,
        "DisputeArmed",
        &[
            (ARMED_BLOCK, u32_bytes(300)),
            (COMMITMENT_HASH, hash20()),
            (TARGET_RESERVES, str_bytes("bcrt1qtarget")),
        ],
    );
}

#[test]
fn schema_ledger_close() {
    validate_schema(60, "LedgerClose", &[]);
}

#[test]
fn schema_transfer_lock() {
    validate_schema(
        70,
        "TransferLock",
        &[
            (NONCE, hash32()),
            (SOURCE_DEPOSIT_ID, deposit_id()),
            (DESTINATION_DEPOSIT_ID, vec![0x02; 16]),
            (AMOUNT, u64_bytes(1_000_000)),
            (FEES, u64_bytes(2000)),
            (COMPLETION_SCRIPT, str_bytes("sha256(abcd1234)")),
            (TIMEOUT_HEIGHT, u32_bytes(5000)),
            (TRANSFER_ID, hash32()),
            (WITNESS, witness_tlv()),
        ],
    );
}

#[test]
fn schema_transfer_complete() {
    validate_schema(
        71,
        "TransferComplete",
        &[(TRANSFER_ID, hash32()), (SCRIPT_WITNESS, witness_tlv())],
    );
}

#[test]
fn schema_transfer_fail() {
    validate_schema(
        72,
        "TransferFail",
        &[
            (TRANSFER_ID, hash32()),
            (BLOCK_HASH, hash32()),
            (FAIL_REASON, u8_bytes(1)),
        ],
    );
}
