//! Audit Ledger Hash Chain Validation Tests
//!
//! Tests that verify audit ledgers maintain a valid hash chain where each
//! message's prev_hash equals the previous message's new_hash.

#![cfg(feature = "bitcoin-deposits")]

/// Validates that a sequence of (prev_hash, new_hash) pairs forms a valid chain.
/// Returns Ok(()) if valid, or Err with description of the break.
fn validate_hash_chain(updates: &[([u8; 32], [u8; 32])]) -> Result<(), String> {
    if updates.is_empty() {
        return Ok(());
    }

    // First update should start from genesis (all zeros)
    let genesis_hash = [0u8; 32];
    if updates[0].0 != genesis_hash {
        return Err(format!(
            "First update should start from genesis hash [00000000...], but starts from [{:02x}{:02x}{:02x}{:02x}...]",
            updates[0].0[0], updates[0].0[1], updates[0].0[2], updates[0].0[3]
        ));
    }

    // Each subsequent update's prev_hash should equal previous update's new_hash
    for i in 1..updates.len() {
        let prev_new_hash = updates[i - 1].1;
        let curr_prev_hash = updates[i].0;

        if curr_prev_hash != prev_new_hash {
            return Err(format!(
                "Hash chain break at update {}: prev_hash [{:02x}{:02x}{:02x}{:02x}...] != previous new_hash [{:02x}{:02x}{:02x}{:02x}...]",
                i,
                curr_prev_hash[0], curr_prev_hash[1], curr_prev_hash[2], curr_prev_hash[3],
                prev_new_hash[0], prev_new_hash[1], prev_new_hash[2], prev_new_hash[3]
            ));
        }
    }

    Ok(())
}

#[test]
fn test_valid_hash_chain() {
    // A valid chain: each prev_hash equals previous new_hash
    let updates = vec![
        ([0u8; 32], [0xcd, 0xfd, 0xf7, 0xd0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        ([0xcd, 0xfd, 0xf7, 0xd0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
         [0x78, 0x6e, 0x8e, 0x7e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        ([0x78, 0x6e, 0x8e, 0x7e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
         [0xc5, 0xea, 0xa7, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    ];

    assert!(validate_hash_chain(&updates).is_ok());
}

#[test]
fn test_chain_not_starting_from_genesis() {
    // Chain starts from non-zero hash - should fail
    let updates = vec![
        ([0x6f, 0xea, 0xda, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
         [0xc5, 0xea, 0xa7, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    ];

    let result = validate_hash_chain(&updates);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("genesis"));
}

#[test]
fn test_chain_with_gap() {
    // Chain has a gap - update 2's prev_hash doesn't match update 1's new_hash
    // This simulates the bug: missing intermediate updates
    let updates = vec![
        // Update 0: [00000000 → cdfdf7d0]
        ([0u8; 32], [0xcd, 0xfd, 0xf7, 0xd0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        // Update 1: [6feadabe → c5eaa702] - WRONG! Should start from cdfdf7d0
        ([0x6f, 0xea, 0xda, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
         [0xc5, 0xea, 0xa7, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    ];

    let result = validate_hash_chain(&updates);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Hash chain break"));
}

#[test]
fn test_real_world_broken_audit_chain() {
    // This represents the actual broken audit chain from the bug report:
    // Auditor only got ReservesToReserves starting at wrong hash
    //
    // Expected direct ledger:
    //   LedgerOpenRequest:    [00000000 → cdfdf7d0]
    //   AddQuorumMember: [cdfdf7d0 → 786e8e7e]
    //   CollateralAttestation:[786e8e7e → 6feadabe]
    //   CollateralAttestation:[6feadabe → b296c726]
    //   ReservesToReserves:   [b296c726 → c5eaa702]
    //
    // Broken audit ledger:
    //   ReservesToReserves:   [6feadabe → c5eaa702]  <- missing 4 updates!

    let broken_audit_updates = vec![
        // Only one update, starting from wrong hash (should be b296c726, not 6feadabe)
        ([0x6f, 0xea, 0xda, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
         [0xc5, 0xea, 0xa7, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    ];

    let result = validate_hash_chain(&broken_audit_updates);
    assert!(result.is_err(), "Broken audit chain should be detected as invalid");

    let error = result.unwrap_err();
    assert!(error.contains("genesis"), "Error should mention genesis hash: {}", error);
}

#[test]
fn test_empty_chain_is_valid() {
    let updates: Vec<([u8; 32], [u8; 32])> = vec![];
    assert!(validate_hash_chain(&updates).is_ok());
}

#[test]
fn test_single_update_from_genesis() {
    let updates = vec![
        ([0u8; 32], [0xab, 0xcd, 0xef, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    ];
    assert!(validate_hash_chain(&updates).is_ok());
}

/// Simulates comparing a direct ledger with an audit ledger to detect missing updates
fn compare_ledgers(
    direct: &[([u8; 32], [u8; 32], &str)],
    audit: &[([u8; 32], [u8; 32], &str)],
) -> Result<(), String> {
    // Validate both chains individually
    let direct_hashes: Vec<_> = direct.iter().map(|(p, n, _)| (*p, *n)).collect();
    let audit_hashes: Vec<_> = audit.iter().map(|(p, n, _)| (*p, *n)).collect();

    validate_hash_chain(&direct_hashes)?;
    validate_hash_chain(&audit_hashes)?;

    // Check that audit ledger's final hash matches direct ledger's final hash
    if !direct.is_empty() && !audit.is_empty() {
        let direct_final = direct.last().unwrap().1;
        let audit_final = audit.last().unwrap().1;

        if direct_final != audit_final {
            return Err(format!(
                "Final hashes don't match: direct [{:02x}{:02x}{:02x}{:02x}...] != audit [{:02x}{:02x}{:02x}{:02x}...]",
                direct_final[0], direct_final[1], direct_final[2], direct_final[3],
                audit_final[0], audit_final[1], audit_final[2], audit_final[3]
            ));
        }
    }

    Ok(())
}

#[test]
fn test_compare_matching_ledgers() {
    let direct = vec![
        ([0u8; 32], [0xaa; 32], "LedgerOpenRequest"),
        ([0xaa; 32], [0xbb; 32], "AddDeposit"),
        ([0xbb; 32], [0xcc; 32], "ReservesToReserves"),
    ];

    let audit = vec![
        ([0u8; 32], [0xaa; 32], "LedgerOpen"),
        ([0xaa; 32], [0xbb; 32], "AddDeposit"),
        ([0xbb; 32], [0xcc; 32], "ReservesToReserves"),
    ];

    assert!(compare_ledgers(&direct, &audit).is_ok());
}

#[test]
fn test_compare_mismatched_final_hash() {
    let direct = vec![
        ([0u8; 32], [0xaa; 32], "LedgerOpenRequest"),
        ([0xaa; 32], [0xbb; 32], "AddDeposit"),
    ];

    // Audit has different final hash
    let audit = vec![
        ([0u8; 32], [0xaa; 32], "LedgerOpen"),
        ([0xaa; 32], [0xff; 32], "AddDeposit"),  // Different!
    ];

    let result = compare_ledgers(&direct, &audit);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Final hashes don't match"));
}
