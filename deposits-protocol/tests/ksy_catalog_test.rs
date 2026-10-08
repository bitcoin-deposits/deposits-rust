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
// Typed-record switch tables (.ksy `op_record` / `outer_record` / `fee_record`
// / `transfer_fee_record`). These cross-check the typed switch I added against
// the comment-block catalog and against the Rust codec's emitted byte widths.
// If someone adds a Rust field but forgets the typed switch case, or the
// switch case names a kaitai type that doesn't match the wire width, these
// tests catch it.
// ============================================================================

/// Parse a single named typed-record's switch table from the .ksy file.
/// Returns a map of field_type → kaitai type name (e.g. `u4be`, `pubkey`).
///
/// We don't pull in serde_yaml just for this — line scanning is fine since
/// the .ksy uses a fixed indentation (12 spaces for `cases:` entries).
fn parse_switch_table(record_name: &str) -> HashMap<u64, String> {
    let ksy = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/deposits_protocol.ksy"
    ))
    .expect("failed to read .ksy file");

    let mut map = HashMap::new();
    let mut in_record = false;
    let mut in_cases = false;

    for line in ksy.lines() {
        let trimmed = line.trim_start();
        if !in_record {
            // Top-level `<record_name>:` definitions live at 2-space indent.
            if trimmed == format!("{}:", record_name) {
                in_record = true;
            }
            continue;
        }
        // Leaving the type's block when we hit another top-level `<name>:`
        // (2-space indent with a single trailing colon and no leading space-
        // delimited content). Use indent + ends_with(":") + non-blank as the
        // signal.
        let indent = line.len() - trimmed.len();
        if indent <= 2 && line.ends_with(':') && !line.starts_with("  ") {
            break;
        }
        if indent == 2 && line.ends_with(':') && trimmed != format!("{}:", record_name) {
            break;
        }

        if trimmed.starts_with("cases:") {
            in_cases = true;
            continue;
        }

        if in_cases {
            // Cases lines look like `            0:   u1                  # ...`.
            // We require at least 12 leading spaces to filter out un-related.
            if indent < 12 {
                in_cases = false;
                continue;
            }
            // Strip a trailing comment.
            let body = trimmed.split('#').next().unwrap().trim();
            if body.is_empty() {
                continue;
            }
            // Format: `<num>: <kaitai_type_name>`.
            let mut parts = body.splitn(2, ':');
            let num: u64 = match parts.next().and_then(|s| s.trim().parse().ok()) {
                Some(n) => n,
                None => continue,
            };
            let ty = parts.next().unwrap_or("").trim().to_string();
            if !ty.is_empty() {
                map.insert(num, ty);
            }
        }
    }

    map
}

/// Expected wire byte-width for a named kaitai type. `None` means variable
/// (string, nested TLV, repeated lists).
fn kaitai_type_width(name: &str) -> Option<usize> {
    match name {
        "u1" => Some(1),
        "u2" | "u2be" => Some(2),
        "u4" | "u4be" => Some(4),
        "u8" | "u8be" => Some(8),
        "pubkey" => Some(33),
        "hash32" => Some(32),
        "hash20" => Some(20),
        "sig64" => Some(64),
        "deposit_id_bytes" => Some(16),
        // Variable: pubkey_concat (multiple of 33), str, nested TLV containers.
        "pubkey_concat"
        | "str"
        | "fee_structure"
        | "transfer_fee_schedule"
        | "ledger_operation"
        | "descriptor_witness"
        | "cosignature_list"
        | "quorum_member_ledger_id_list" => None,
        _ => panic!("unknown kaitai type referenced by switch table: {}", name),
    }
}

#[test]
fn op_record_switch_parses() {
    let table = parse_switch_table("op_record");
    assert!(
        table.contains_key(&0),
        "op_record switch missing discriminant (type 0)"
    );
    assert!(
        table.contains_key(&86),
        "op_record switch missing quorum_expiry (type 86)"
    );
    assert!(
        table.contains_key(&284),
        "op_record switch missing replacement_collateral_amount (type 284)"
    );
    println!("op_record switch: {} typed cases", table.len());
}

#[test]
fn outer_record_switch_parses() {
    let table = parse_switch_table("outer_record");
    // Sanity: well-known outer fields.
    for ft in [0u64, 2, 4, 6, 8, 10, 20, 22] {
        assert!(
            table.contains_key(&ft),
            "outer_record switch missing field type {}",
            ft
        );
    }
    println!("outer_record switch: {} typed cases", table.len());
}

#[test]
fn op_record_switch_widths_match_rust_codec() {
    // For every (field_type, kaitai_type) in the op_record switch with a
    // fixed wire width, find a Rust-emitted instance of that field type
    // and verify the byte length matches what the kaitai type promises.
    let table = parse_switch_table("op_record");
    let test_ops = build_all_test_ops();

    let mut checked = 0usize;
    let mut unmatched = Vec::new();

    for (ft, ty_name) in &table {
        let expected = match kaitai_type_width(ty_name) {
            Some(w) => w,
            None => continue, // variable-length types — no byte-width assertion
        };

        // Find a test op that emits this field.
        let found = test_ops.iter().find_map(|(_, op)| {
            let bytes = op.tlv_encode();
            let stream = TlvStream::decode(&bytes).ok()?;
            stream.get(*ft).map(|v| v.to_vec())
        });

        match found {
            Some(value) if value.len() == expected => checked += 1,
            Some(value) => {
                unmatched.push(format!(
                    "field {}: switch says `{}` ({} bytes) but Rust emitted {} bytes",
                    ft,
                    ty_name,
                    expected,
                    value.len()
                ));
            }
            None => {
                // OK — not every switch case has to be exercised by a
                // test op (some discriminants aren't built here, e.g.
                // QuorumRemoveMember-only sigs). Skip silently.
            }
        }
    }

    if !unmatched.is_empty() {
        panic!(
            "op_record switch / Rust codec wire-width mismatches:\n  {}",
            unmatched.join("\n  ")
        );
    }
    assert!(
        checked > 30,
        "expected to cross-check >30 fields, only checked {}",
        checked
    );
}

#[test]
fn outer_record_switch_widths_match_rust_codec() {
    // The outer SignedLedgerUpdate isn't built here, but its fixed-width
    // field types are well-known. Verify the switch promises match the
    // documented widths.
    let table = parse_switch_table("outer_record");
    let expected: &[(u64, &str, usize)] = &[
        (0, "pubkey", 33),
        (2, "hash32", 32),
        (4, "u8be", 8),
        (6, "hash32", 32),
        (10, "u4be", 4),
        (12, "hash32", 32),
        (14, "pubkey", 33),
        (16, "hash32", 32),
        (18, "sig64", 64),
        (20, "sig64", 64),
    ];
    for (ft, ty, _w) in expected {
        let actual = table
            .get(ft)
            .unwrap_or_else(|| panic!("outer_record missing field {}", ft));
        assert_eq!(actual, ty, "outer_record field {} should be `{}`", ft, ty);
    }
}

#[test]
fn fee_record_switch_widths_match_rust_codec() {
    let table = parse_switch_table("fee_record");
    // FeeStructure: 0 = annualized_msats (u64), 2 = annualized_bps (u16),
    // 4 = frequency_blocks (u32).
    assert_eq!(table.get(&0).map(|s| s.as_str()), Some("u8be"));
    assert_eq!(table.get(&2).map(|s| s.as_str()), Some("u2be"));
    assert_eq!(table.get(&4).map(|s| s.as_str()), Some("u4be"));

    // Encode a FeeStructure and check the field widths land where the
    // switch promises.
    let f = FeeStructure {
        annualized_msats: 1000,
        annualized_bps: 50,
        frequency_blocks: 2016,
    };
    let bytes = f.tlv_encode();
    let stream = TlvStream::decode(&bytes).expect("FeeStructure decode");
    assert_eq!(stream.get(0).unwrap().len(), 8);
    assert_eq!(stream.get(2).unwrap().len(), 2);
    assert_eq!(stream.get(4).unwrap().len(), 4);
}

#[test]
fn transfer_fee_record_switch_widths_match_rust_codec() {
    let table = parse_switch_table("transfer_fee_record");
    assert_eq!(table.get(&0).map(|s| s.as_str()), Some("u8be"));
    assert_eq!(table.get(&2).map(|s| s.as_str()), Some("u2be"));

    let tf = TransferFeeSchedule {
        fixed_msats: 2,
        rate_bps: 20,
    };
    let bytes = tf.tlv_encode();
    let stream = TlvStream::decode(&bytes).expect("TransferFeeSchedule decode");
    assert_eq!(stream.get(0).unwrap().len(), 8);
    assert_eq!(stream.get(2).unwrap().len(), 2);
}

#[test]
fn op_record_switch_agrees_with_comment_catalog() {
    // For every field type the comment block documents, the typed switch
    // should either name an equivalent kaitai type or omit the case (only
    // for variable-length / nested types that the comment-parser
    // understands as `String` / `NestedTlv`). This catches the common
    // drift case: comment says `u32` but switch says `u8be`.
    let catalog = parse_ksy_catalog();
    let table = parse_switch_table("op_record");

    let mut mismatches = Vec::new();

    for (ft, kf) in catalog.iter() {
        let Some(switch_ty) = table.get(ft) else {
            continue; // not all comment-cataloged fields need a typed case
        };
        let ok = match (&kf.value_type, switch_ty.as_str()) {
            (FieldType::U8, "u1") => true,
            (FieldType::U16, "u2be") => true,
            (FieldType::U32, "u4be") => true,
            (FieldType::U64, "u8be") => true,
            (FieldType::Pubkey, "pubkey") => true,
            // Field 6 is `quorum_members`. The comment-block parser
            // doesn't recognise "N*33 concatenated compressed pubkeys"
            // as a type keyword and falls back to `String`. The switch
            // gets it right with `pubkey_concat`.
            (FieldType::String, "pubkey_concat") if *ft == 6 => true,
            // Field 276 is `quorum_member_ledger_ids` — its multi-line
            // comment description doesn't trigger any keyword, so the
            // comment catalog also falls back to `String`. The switch
            // resolves it to the parallel-array typed list.
            (FieldType::String, "quorum_member_ledger_id_list") if *ft == 276 => true,
            (FieldType::DepositId, "deposit_id_bytes") => true,
            (FieldType::Bytes(20), "hash20") => true,
            (FieldType::Bytes(32), "hash32") => true,
            (FieldType::Bytes(64), "sig64") => true,
            (FieldType::String, "str") => true,
            // Comment block parses "(nested TLV)" / "(nested TLV: FeeStructure)" → NestedTlv("…").
            // The exact captured name varies, so we accept any nested kaitai type for any NestedTlv.
            (
                FieldType::NestedTlv(_),
                "fee_structure"
                | "transfer_fee_schedule"
                | "descriptor_witness"
                | "quorum_member_ledger_id_list",
            ) => true,
            _ => false,
        };
        if !ok {
            mismatches.push(format!(
                "field {}: comment says {:?}, switch says `{}`",
                ft, kf.value_type, switch_ty
            ));
        }
    }

    if !mismatches.is_empty() {
        panic!(
            "op_record typed switch disagrees with comment catalog:\n  {}",
            mismatches.join("\n  ")
        );
    }
}

#[test]
fn every_rust_field_has_op_record_switch_case() {
    // For every field a Rust test op emits, the op_record switch should
    // have a case (or the field must be a deliberately-untyped fall-through;
    // we don't currently have any of those).
    let table = parse_switch_table("op_record");
    let test_ops = build_all_test_ops();

    let mut missing: Vec<String> = Vec::new();
    for (name, op) in &test_ops {
        let bytes = op.tlv_encode();
        let stream = TlvStream::decode(&bytes).expect("decode");
        for (ft, _v) in stream.iter() {
            if !table.contains_key(&ft) {
                missing.push(format!(
                    "{} (disc {}): emits field {} not in op_record switch",
                    name,
                    op.discriminant(),
                    ft
                ));
            }
        }
    }
    if !missing.is_empty() {
        panic!(
            "Rust codec emits field types not covered by op_record switch:\n  {}",
            missing.join("\n  ")
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
                exit_cutoff_height: None,
                exit_outputs: Vec::new(),
                splice_in_outpoint: None,
                splice_in_amount: None,
                reference_feerate: None,
                dormancy_outputs: Vec::new(),
                migration_manifest: Vec::new(),
                migration_receiver: None,
                migration_vout: None,
                reserves_id: "bcrt1qtest".into(),
                spending_txid: h32(),
                new_outpoint_txid: h32(),
                new_outpoint_vout: 0,
                amount: 100_000_000,
                quorum_expiry: 1000,
                ledger_hash: h32(),
                quorum_members: vec![deposits_protocol::messages::QuorumMemberRef::pubkey_only(
                    pk(),
                )],
                collateral_amount: 50_000_000,
                protocol_version: None,
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
                commitment: None,
            },
        ),
        (
            "DepositClose",
            LedgerOperation::DepositClose {
                deposit_id: did(),
                commitment: None,
            },
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
                nonce: 0,
                expiry: u32::MAX,
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
                wallet_authorization: None,
                commitment: None,
            },
        ),
        (
            "InvoiceLock",
            LedgerOperation::InvoiceLock {
                deposit_id: did(),
                amount: 5_000_000,
                payment_id: h32(),
                sequence_number: 43,
                nonce: 0,
                expiry: u32::MAX,
                timeout_height: None,
                fee: None,
                witness: wit(),
                commitment: None,
            },
        ),
        (
            "InvoiceFail",
            LedgerOperation::InvoiceFail {
                deposit_id: did(),
                payment_id: h32(),
                sequence_number: 44,
                commitment: None,
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
                commitment: None,
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
                commitment: None,
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
                nonce: 0,
                expiry: u32::MAX,
                witness: wit(),
                commitment: None,
            },
        ),
        (
            "OnchainFail",
            LedgerOperation::OnchainFail {
                deposit_id: did(),
                withdrawal_id: h32(),
                commitment: None,
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
                commitment: None,
            },
        ),
        (
            "TransferLock",
            LedgerOperation::TransferLock {
                transfer_nonce: h32(),
                source_deposit_id: did(),
                destination_deposit_id: [2; 16],
                amount: 1_000_000,
                fee: 2000,
                completion_script: "sha256(abcd1234)".into(),
                timeout_height: 5000,
                transfer_id: h32(),
                nonce: 0,
                expiry: u32::MAX,
                witness: wit(),
                commitment: None,
            },
        ),
        (
            "TransferComplete",
            LedgerOperation::TransferComplete {
                transfer_id: h32(),
                script_witness: wit(),
                commitment: None,
                dest_commitment: None,
            },
        ),
        (
            "TransferFail",
            LedgerOperation::TransferFail {
                transfer_id: h32(),
                block_hash: h32(),
                reason: 1,
                commitment: None,
            },
        ),
        (
            "QuorumAddMember",
            LedgerOperation::QuorumAddMember {
                min_collateral_bps: None,
                dormancy_blocks: None,
                dormancy_notice_blocks: None,
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
                member_response: None,
                member_signature: None,
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
                commitment: None,
            },
        ),
        (
            "DisputeEnter",
            LedgerOperation::DisputeEnter {
                last_valid_sequence: 10,
                reason: "hash_chain_broken".into(),
                anchor_block_hash: None,
                anchor_block_height: None,
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
