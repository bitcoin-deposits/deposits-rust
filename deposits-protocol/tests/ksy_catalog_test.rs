//! Parses the TLV field type reference comments from deposits_protocol.ksy at test time,
//! builds a field catalog, then for each LedgerOperation discriminant:
//! 1. Generates a TLV payload using only fields from the parsed catalog
//! 2. Produces dummy values sized to match the catalog's type annotations
//! 3. Decodes with Rust, re-encodes, and verifies byte-exact roundtrip
//!
//! This ensures the .ksy comments are the single source of truth for the wire format.

use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::tlv::{write_varint, TlvDecode, TlvEncode, TlvStream};
use deposits_protocol::types::{FeeStructure, TransferFeeSchedule};
use std::collections::HashMap;

// ============================================================================
// .ksy comment parser
// ============================================================================

/// A field from the .ksy catalog
#[derive(Debug, Clone)]
struct KsyField {
    type_num: u64,
    name: String,
    value_type: FieldType,
}

#[derive(Debug, Clone)]
enum FieldType {
    U8,
    U16,
    U32,
    U64,
    Bytes(usize), // fixed size
    String,
    Pubkey,            // 33 bytes compressed secp256k1
    DepositId,         // 16 bytes
    NestedTlv(String), // name of nested type
}

/// Parse the .ksy file's TLV field type reference comments into a catalog
fn parse_ksy_catalog() -> HashMap<u64, KsyField> {
    let ksy = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/deposits_protocol.ksy"
    ))
    .expect("failed to read .ksy file");

    let mut catalog = HashMap::new();

    for line in ksy.lines() {
        let line = line.trim();
        // Match lines like: #   42  = ledger_hash (32 bytes)
        //                   #   200 = deposit_id (16 bytes)
        //                   #   12  = fees (nested TLV: FeeStructure ...)
        if !line.starts_with('#') {
            continue;
        }
        let line = line.trim_start_matches('#').trim();

        // Pattern: NUMBER = NAME (TYPE_DESC)
        let parts: Vec<&str> = line.splitn(2, '=').collect();
        if parts.len() != 2 {
            continue;
        }

        let type_num: u64 = match parts[0].trim().parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let rest = parts[1].trim();
        // Split "name (type_desc)" or just "name"
        let (name, type_desc) = if let Some(paren_start) = rest.find('(') {
            let name = rest[..paren_start].trim();
            let desc = rest[paren_start + 1..].trim_end_matches(')').trim();
            (name, desc)
        } else {
            (rest, "")
        };

        let value_type = parse_field_type(type_desc);

        catalog.insert(
            type_num,
            KsyField {
                type_num,
                name: name.to_string(),
                value_type,
            },
        );
    }

    catalog
}

fn parse_field_type(desc: &str) -> FieldType {
    let desc_lower = desc.to_lowercase();
    if desc_lower.contains("nested tlv") {
        let name = desc
            .split(':')
            .nth(1)
            .unwrap_or("unknown")
            .trim()
            .split(|c: char| !c.is_alphanumeric())
            .next()
            .unwrap_or("unknown");
        return FieldType::NestedTlv(name.to_string());
    }
    if desc_lower.contains("33 bytes") || desc_lower.contains("compressed secp256k1") {
        return FieldType::Pubkey;
    }
    if desc_lower.contains("16 bytes") {
        return FieldType::DepositId;
    }
    if desc_lower.contains("64 bytes") {
        return FieldType::Bytes(64);
    }
    if desc_lower.contains("32 bytes") {
        return FieldType::Bytes(32);
    }
    if desc_lower.contains("20 bytes") || desc_lower.contains("17-20 bytes") {
        return FieldType::Bytes(20);
    }
    if desc_lower == "u8" || desc_lower.contains("u8") {
        return FieldType::U8;
    }
    if desc_lower == "u16" || desc_lower.contains("u16") {
        return FieldType::U16;
    }
    if desc_lower == "u32" || desc_lower.contains("u32") {
        return FieldType::U32;
    }
    if desc_lower == "u64" || desc_lower.contains("u64") {
        return FieldType::U64;
    }
    if desc_lower.contains("string") || desc_lower.contains("variable-length") {
        return FieldType::String;
    }
    if desc_lower.contains("bytes") {
        // Generic bytes — try to parse size
        if let Some(n) = desc_lower
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<usize>().ok())
        {
            return FieldType::Bytes(n);
        }
        return FieldType::Bytes(32); // default
    }
    // Fallback
    FieldType::String
}

// ============================================================================
// Value generators (special cases for validated fields)
// ============================================================================

fn generate_value_for_disc(field: &KsyField, disc: u8) -> Vec<u8> {
    // Special-case generators for fields that have validation constraints
    match field.type_num {
        // operator_id / pubkey fields need a valid compressed secp256k1 point
        10 | 38 | 44 | 56 | 108 => {
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap()
        }
        // quorum_members: concatenated 33-byte compressed pubkeys
        6 => hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap(),
        // Field 12 is overloaded: nested FeeStructure in DepositOpen (20), plain u64 fee elsewhere
        12 => {
            if disc == 20 || disc == 22 {
                // DepositOpen / FeeChange: nested FeeStructure
                let f = FeeStructure {
                    annualized_msats: 1000,
                    annualized_bps: 50,
                    frequency_blocks: 2016,
                };
                f.tlv_encode()
            } else {
                // OnchainLock (36), TransferLock (70), etc: plain u64 fee
                500u64.to_be_bytes().to_vec()
            }
        }
        // Nested TransferFeeSchedule
        226 => {
            let tf = TransferFeeSchedule {
                fixed_msats: 2,
                rate_bps: 20,
            };
            tf.tlv_encode()
        }
        // Witness (nested TLV with stack elements)
        204 | 224 => {
            let mut buf = Vec::new();
            write_varint(&mut buf, 1).unwrap();
            write_varint(&mut buf, 64).unwrap();
            buf.extend_from_slice(&[0x30; 64]);
            buf
        }
        // nested FeeStructure (new_fees)
        20 => {
            let f = FeeStructure {
                annualized_msats: 500,
                annualized_bps: 25,
                frequency_blocks: 1008,
            };
            f.tlv_encode()
        }
        // Default: generate from type annotation
        _ => generate_from_type(&field.value_type),
    }
}

fn generate_from_type(ft: &FieldType) -> Vec<u8> {
    match ft {
        FieldType::U8 => vec![42],
        FieldType::U16 => 1000u16.to_be_bytes().to_vec(),
        FieldType::U32 => 100_000u32.to_be_bytes().to_vec(),
        FieldType::U64 => 10_000_000u64.to_be_bytes().to_vec(),
        FieldType::Bytes(n) => vec![0xab; *n],
        FieldType::String => b"test_value".to_vec(),
        FieldType::Pubkey => {
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap()
        }
        FieldType::DepositId => vec![0x01; 16],
        FieldType::NestedTlv(_) => {
            // Generic nested — empty TLV
            let f = FeeStructure {
                annualized_msats: 100,
                annualized_bps: 10,
                frequency_blocks: 144,
            };
            f.tlv_encode()
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[test]
fn ksy_catalog_parses_successfully() {
    let catalog = parse_ksy_catalog();
    // Should have at least the common fields
    assert!(catalog.contains_key(&0), "missing discriminant field (0)");
    assert!(catalog.contains_key(&2), "missing amount field (2)");
    assert!(catalog.contains_key(&200), "missing deposit_id field (200)");
    assert!(catalog.contains_key(&210), "missing nonce field (210)");
    println!("Parsed {} fields from .ksy catalog", catalog.len());
    for (t, f) in catalog.iter() {
        println!("  {:>3} = {} ({:?})", t, f.name, f.value_type);
    }
}

#[test]
fn every_rust_field_is_in_ksy_catalog() {
    let catalog = parse_ksy_catalog();

    // For each discriminant, encode a Rust object and check all its field types are cataloged
    let test_ops = build_all_test_ops();

    let mut undocumented = Vec::new();

    for (name, op) in &test_ops {
        let encoded = op.tlv_encode();
        let stream = TlvStream::decode(&encoded).expect("decode failed");

        for (field_type, _value) in stream.iter() {
            if field_type == 0 {
                continue;
            } // discriminant always present
            if !catalog.contains_key(&field_type) {
                undocumented.push(format!(
                    "{} (disc {}): uses field type {} not in .ksy catalog",
                    name,
                    op.discriminant(),
                    field_type
                ));
            }
        }
    }

    if !undocumented.is_empty() {
        panic!("Undocumented field types:\n{}", undocumented.join("\n"));
    }
}

#[test]
fn ksy_generated_payloads_roundtrip() {
    let catalog = parse_ksy_catalog();

    // For each discriminant, encode a Rust object, extract its field types,
    // rebuild from catalog-generated values, and verify roundtrip
    let test_ops = build_all_test_ops();

    for (name, op) in &test_ops {
        let disc = op.discriminant();
        let encoded = op.tlv_encode();
        let stream = TlvStream::decode(&encoded).expect("decode failed");

        // Collect field types this operation uses
        let field_types: Vec<u64> = stream.iter().map(|(t, _)| t).filter(|t| *t != 0).collect();

        // Build payload from catalog values
        let mut new_stream = TlvStream::new();
        new_stream.insert(0, vec![disc]);

        for ft in &field_types {
            if let Some(field) = catalog.get(ft) {
                new_stream.insert(*ft, generate_value_for_disc(field, disc));
            } else {
                panic!("[{}] field type {} not in catalog", name, ft);
            }
        }

        let catalog_bytes = new_stream.encode();

        // Rust decode
        let decoded = match LedgerOperation::tlv_decode(&catalog_bytes) {
            Ok(d) => d,
            Err(e) => {
                panic!("[{}] disc={}: Rust can't decode catalog-generated payload: {:?}\n  field_types: {:?}",
                    name, disc, e, field_types);
            }
        };

        assert_eq!(
            decoded.discriminant(),
            disc,
            "[{}]: discriminant mismatch",
            name
        );

        // Re-encode and verify byte-exact roundtrip
        let re_encoded = decoded.tlv_encode();
        assert_eq!(
            re_encoded, catalog_bytes,
            "[{}] disc={}: re-encode differs from catalog-generated bytes",
            name, disc
        );
    }
}

// ============================================================================
// Build one test operation per discriminant
// ============================================================================

fn pk() -> bitcoin::secp256k1::PublicKey {
    use std::str::FromStr;
    bitcoin::secp256k1::PublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap()
}
fn did() -> [u8; 16] {
    [0x01; 16]
}
fn h32() -> [u8; 32] {
    [0xab; 32]
}
fn h20() -> [u8; 20] {
    [0xab; 20]
}
fn sig() -> [u8; 64] {
    [0x30; 64]
}
fn fees() -> FeeStructure {
    FeeStructure {
        annualized_msats: 1000,
        annualized_bps: 50,
        frequency_blocks: 2016,
    }
}
fn tfees() -> TransferFeeSchedule {
    TransferFeeSchedule {
        fixed_msats: 2,
        rate_bps: 20,
    }
}
fn wit() -> deposits_protocol::types::DescriptorWitness {
    deposits_protocol::types::DescriptorWitness {
        stack: vec![vec![0x30; 64]],
    }
}

fn build_all_test_ops() -> Vec<(&'static str, LedgerOperation)> {
    vec![
        (
            "LedgerOpen",
            LedgerOperation::LedgerOpen {
                operator_id: pk(),
                reserves_id: "bcrt1qtest".into(),
                genesis_block: 100,
                reserves_amount: 100_000_000,
                collateral_amount: 0,
            },
        ),
        (
            "QuorumBegin",
            LedgerOperation::QuorumBegin {
                reserves_id: "bcrt1qtest".into(),
                spending_txid: h32(),
                new_outpoint_txid: h32(),
                new_outpoint_vout: 0,
                amount: 100_000_000,
                quorum_expiry: 1000,
                ledger_hash: h32(),
                quorum_members: vec![deposits_protocol::messages::QuorumMemberRef::pubkey_only(pk())],
                collateral_amount: 50_000_000,
            },
        ),
        (
            "DepositOpen",
            LedgerOperation::DepositOpen {
                deposit_id: did(),
                descriptor: "pk(0279be66...)".into(),
                fees: Some(fees()),
                transfer_fees: Some(tfees()),
                payment_hash: Some(h32()),
                invoice: Some("lnbcrt1test".into()),
                cosigner_guarantee_signature: Some(sig()),

                receive_requires_sig: false,
                fee_change_after_blocks: None,
                fee_change_notice_blocks: None,
                fee_change_limit_bps: None,
            },
        ),
        (
            "DepositClose",
            LedgerOperation::DepositClose { deposit_id: did() },
        ),
        (
            "FeeChange",
            LedgerOperation::FeeChange {
                deposit_id: did(),
                new_fees: fees(),
                effective_block: 0,
            },
        ),
        (
            "DepositKeyRotate",
            LedgerOperation::DepositKeyRotate {
                deposit_id: did(),
                new_descriptor: "pk(03...)".into(),
                witness: wit(),
            },
        ),
        (
            "InvoiceCredit",
            LedgerOperation::InvoiceCredit {
                payment_hash: h32(),
                deposit_id: did(),
                amount: 10_000_000,
                invoice_id: "bolt11:test".into(),
                sequence_number: 42,
            },
        ),
        (
            "InvoiceLock",
            LedgerOperation::InvoiceLock {
                deposit_id: did(),
                amount: 5_000_000,
                payment_id: h32(),
                sequence_number: 43,
                witness: wit(),
            },
        ),
        (
            "InvoiceFail",
            LedgerOperation::InvoiceFail {
                deposit_id: did(),
                amount: 5_000_000,
                payment_id: h32(),
                sequence_number: 44,
            },
        ),
        (
            "InvoiceFulfill",
            LedgerOperation::InvoiceFulfill {
                deposit_id: did(),
                amount: 5_000_000,
                payment_id: h32(),
                sequence_number: 45,
                witness: wit(),
                preimage: h32(),
            },
        ),
        (
            "OnchainCredit",
            LedgerOperation::OnchainCredit {
                txid: h32(),
                vout: 0,
                deposit_id: did(),
                amount: 100_000_000,
                funding_address: "bcrt1qfund".into(),
            },
        ),
        (
            "OnchainLock",
            LedgerOperation::OnchainLock {
                deposit_id: did(),
                amount: 50_000_000,
                fee_sats: 500,
                destination_address: "bcrt1qdest".into(),
                withdrawal_id: h32(),
                witness: wit(),
            },
        ),
        (
            "OnchainFail",
            LedgerOperation::OnchainFail {
                deposit_id: did(),
                withdrawal_id: h32(),
            },
        ),
        (
            "OnchainFulfill",
            LedgerOperation::OnchainFulfill {
                deposit_id: did(),
                withdrawal_id: h32(),
                amount: 50_000_000,
                txid: h32(),
                destination_address: "bcrt1qdest".into(),
            },
        ),
        (
            "TransferLock",
            LedgerOperation::TransferLock {
                nonce: h32(),
                source_deposit_id: did(),
                destination_deposit_id: [2; 16],
                amount: 1_000_000,
                fee: 2000,
                completion_script: "sha256(abcd1234)".into(),
                timeout_height: 5000,
                transfer_id: h32(),
                witness: wit(),
            },
        ),
        (
            "TransferComplete",
            LedgerOperation::TransferComplete {
                transfer_id: h32(),
                script_witness: wit(),
            },
        ),
        (
            "TransferFail",
            LedgerOperation::TransferFail {
                transfer_id: h32(),
                block_hash: h32(),
                reason: 1,
            },
        ),
        (
            "QuorumAddMember",
            LedgerOperation::QuorumAddMember {
                quorum_member: pk(),
                quorum_member_signature: sig(),
                member_ledger_id: "abc123".into(),
                min_fee_bps: Some(500),
                min_fee_fixed: Some(100_000),
                max_fee_period: Some(2016),
                membership_until: Some(10000),
                dispute_response_blocks: None,
                dispute_arm_blocks: None,
                service_response_blocks: None,
                max_transfer_timeout_blocks: None,
                max_descriptor_bytes: None,
                compensation_bps: None,
                compensation_deposit_id: None,
                compensation_frequency_blocks: None,
            },
        ),
        (
            "QuorumRemoveMember",
            LedgerOperation::QuorumRemoveMember {
                quorum_member: pk(),
                operator_signature: sig(),
            },
        ),
        (
            "QuorumJoin",
            LedgerOperation::QuorumJoin {
                operator_id: pk(),
                ledger_id: "abc123def456".into(),
                membership_expires: 100_000,
            },
        ),
        (
            "FeeCollect",
            LedgerOperation::FeeCollect {
                deposit_id: did(),
                amount: 1000,
                block_height: 500,
            },
        ),
        (
            "DisputeEnter",
            LedgerOperation::DisputeEnter {
                last_valid_sequence: 10,
                reason: "hash_chain_broken".into(),
            },
        ),
        (
            "DisputeArmed",
            LedgerOperation::DisputeArmed {
                armed_block: 300,
                commitment_hash: h20(),
                target_reserves: "bcrt1qtarget".into(),
                replacement_collateral: None,
            },
        ),
        (
            "DisputeAcquire",
            LedgerOperation::DisputeAcquire {
                new_custodian: pk(),
                claim_txid: h32(),
                new_reserves_address: "bcrt1qnew".into(),
            },
        ),
        ("DisputeYield", LedgerOperation::DisputeYield),
        ("LedgerClose", LedgerOperation::LedgerClose),
    ]
}
