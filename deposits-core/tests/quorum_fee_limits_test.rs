//! Tests for quorum member fee limits on QuorumAddMember.
//!
//! Quorum members specify minimum fee requirements when joining. These protect
//! members from inheriting low-fee obligations if custody transfers. Deposits
//! must meet the strictest quorum member minimums.

use deposits_core::ledger::{Ledger, LedgerRole};
use deposits_core::messages::LedgerOperation;
use deposits_core::types::{
    compute_deposit_id, FeeStructure, LedgerState, QuorumMember, TransferFeeSchedule,
};
use deposits_protocol::TlvEncode;
use deposits_protocol::TlvDecode;

fn test_pubkey() -> bitcoin::secp256k1::PublicKey {
    use std::str::FromStr;
    bitcoin::secp256k1::PublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap()
}

fn test_pubkey_2() -> bitcoin::secp256k1::PublicKey {
    use std::str::FromStr;
    bitcoin::secp256k1::PublicKey::from_str(
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    )
    .unwrap()
}

fn test_pubkey_3() -> bitcoin::secp256k1::PublicKey {
    use std::str::FromStr;
    bitcoin::secp256k1::PublicKey::from_str(
        "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    )
    .unwrap()
}

fn make_ledger() -> Ledger {
    let state = LedgerState::new(
        test_pubkey(),
        "bcrt1qtest".to_string(),
        "bcrt1qaddr".to_string(),
        0,
    );
    Ledger {
        state,
        role: LedgerRole::Operator,
        history: Vec::new(),
    }
}

fn add_member(
    ledger: &mut Ledger,
    member: bitcoin::secp256k1::PublicKey,
    min_fee_bps: Option<u16>,
    min_fee_fixed: Option<u64>,
    max_fee_period: Option<u32>,
) {
    ledger
        .apply_state_changes(&LedgerOperation::QuorumAddMember {
            quorum_member: member,
            quorum_member_signature: [0u8; 64],
            member_ledger_id: "abc123".repeat(11)[..64].to_string(),
            min_fee_bps,
            min_fee_fixed,
            max_fee_period,
            collateral_lock_amount: None,
            collateral_lock_until: None,
        })
        .unwrap();
}

/// Compute the strictest fee limits across all quorum members.
/// Returns (min_bps, min_fixed, max_period) — each is the most restrictive value.
fn strictest_quorum_limits(members: &[QuorumMember]) -> (Option<u16>, Option<u64>, Option<u32>) {
    let mut min_bps: Option<u16> = None;
    let mut min_fixed: Option<u64> = None;
    let mut max_period: Option<u32> = None;

    for m in members {
        if let Some(bps) = m.min_fee_bps {
            min_bps = Some(min_bps.map_or(bps, |cur: u16| cur.max(bps)));
        }
        if let Some(fixed) = m.min_fee_fixed {
            min_fixed = Some(min_fixed.map_or(fixed, |cur: u64| cur.max(fixed)));
        }
        if let Some(period) = m.max_fee_period {
            // Strictest = smallest max period (member wants more frequent collection)
            max_period = Some(max_period.map_or(period, |cur: u32| cur.min(period)));
        }
    }

    (min_bps, min_fixed, max_period)
}

/// Check if a fee structure meets quorum limits.
fn fees_meet_quorum_limits(
    fees: &FeeStructure,
    members: &[QuorumMember],
) -> Result<(), String> {
    let (min_bps, min_fixed, max_period) = strictest_quorum_limits(members);

    if let Some(required_bps) = min_bps {
        if fees.annualized_bps < required_bps {
            return Err(format!(
                "Fee rate {} bps below quorum minimum {} bps",
                fees.annualized_bps, required_bps
            ));
        }
    }

    if let Some(required_fixed) = min_fixed {
        if fees.annualized_fixed < required_fixed {
            return Err(format!(
                "Fixed fee {} below quorum minimum {}",
                fees.annualized_fixed, required_fixed
            ));
        }
    }

    if let Some(required_max_period) = max_period {
        if fees.frequency_blocks > required_max_period {
            return Err(format!(
                "Fee period {} blocks exceeds quorum maximum {} blocks",
                fees.frequency_blocks, required_max_period
            ));
        }
    }

    Ok(())
}

// =========================================================================
// Fee limits stored on QuorumMember
// =========================================================================

#[test]
fn quorum_add_member_stores_fee_limits() {
    let mut ledger = make_ledger();
    add_member(&mut ledger, test_pubkey_2(), Some(50), Some(10_000), Some(2016));

    assert_eq!(ledger.state.quorum_members.len(), 1);
    let member = &ledger.state.quorum_members[0];
    assert_eq!(member.min_fee_bps, Some(50));
    assert_eq!(member.min_fee_fixed, Some(10_000));
    assert_eq!(member.max_fee_period, Some(2016));
}

#[test]
fn quorum_add_member_without_limits() {
    let mut ledger = make_ledger();
    add_member(&mut ledger, test_pubkey_2(), None, None, None);

    let member = &ledger.state.quorum_members[0];
    assert_eq!(member.min_fee_bps, None);
    assert_eq!(member.min_fee_fixed, None);
    assert_eq!(member.max_fee_period, None);
}

#[test]
fn quorum_add_member_partial_limits() {
    let mut ledger = make_ledger();
    // Only constrain bps, leave others open
    add_member(&mut ledger, test_pubkey_2(), Some(100), None, None);

    let member = &ledger.state.quorum_members[0];
    assert_eq!(member.min_fee_bps, Some(100));
    assert_eq!(member.min_fee_fixed, None);
    assert_eq!(member.max_fee_period, None);
}

// =========================================================================
// TLV roundtrip
// =========================================================================

#[test]
fn quorum_add_member_fee_limits_tlv_roundtrip() {
    let op = LedgerOperation::QuorumAddMember {
        quorum_member: test_pubkey_2(),
        quorum_member_signature: [0xAA; 64],
        member_ledger_id: "a".repeat(64),
        min_fee_bps: Some(200),
        min_fee_fixed: Some(50_000),
        max_fee_period: Some(4032),
        collateral_lock_amount: None,
        collateral_lock_until: None,
    };

    let encoded = op.tlv_encode();
    let decoded = LedgerOperation::tlv_decode(&encoded).unwrap();

    if let LedgerOperation::QuorumAddMember {
        min_fee_bps,
        min_fee_fixed,
        max_fee_period,
        ..
    } = decoded
    {
        assert_eq!(min_fee_bps, Some(200));
        assert_eq!(min_fee_fixed, Some(50_000));
        assert_eq!(max_fee_period, Some(4032));
    } else {
        panic!("decoded wrong variant");
    }
}

#[test]
fn quorum_add_member_no_limits_tlv_roundtrip() {
    let op = LedgerOperation::QuorumAddMember {
        quorum_member: test_pubkey_2(),
        quorum_member_signature: [0xBB; 64],
        member_ledger_id: "b".repeat(64),
        min_fee_bps: None,
        min_fee_fixed: None,
        max_fee_period: None,
        collateral_lock_amount: None,
        collateral_lock_until: None,
    };

    let encoded = op.tlv_encode();
    let decoded = LedgerOperation::tlv_decode(&encoded).unwrap();

    if let LedgerOperation::QuorumAddMember {
        min_fee_bps,
        min_fee_fixed,
        max_fee_period,
        ..
    } = decoded
    {
        assert_eq!(min_fee_bps, None);
        assert_eq!(min_fee_fixed, None);
        assert_eq!(max_fee_period, None);
    } else {
        panic!("decoded wrong variant");
    }
}

// =========================================================================
// Strictest limits across multiple members
// =========================================================================

#[test]
fn strictest_limits_single_member() {
    let members = vec![QuorumMember {
        pubkey: test_pubkey_2(),
        ledger_id: String::new(),
        min_fee_bps: Some(50),
        min_fee_fixed: Some(1000),
        max_fee_period: Some(2016),
        collateral_lock_amount: None,
        collateral_lock_until: None,
    }];

    let (bps, fixed, period) = strictest_quorum_limits(&members);
    assert_eq!(bps, Some(50));
    assert_eq!(fixed, Some(1000));
    assert_eq!(period, Some(2016));
}

#[test]
fn strictest_limits_multiple_members_takes_most_restrictive() {
    let members = vec![
        QuorumMember {
            pubkey: test_pubkey_2(),
            ledger_id: String::new(),
            min_fee_bps: Some(50),    // less strict
            min_fee_fixed: Some(5000), // more strict
            max_fee_period: Some(4032), // less strict (longer period allowed)
            collateral_lock_amount: None,
            collateral_lock_until: None,
        },
        QuorumMember {
            pubkey: test_pubkey_3(),
            ledger_id: String::new(),
            min_fee_bps: Some(100),   // more strict (higher min)
            min_fee_fixed: Some(1000), // less strict
            max_fee_period: Some(2016), // more strict (shorter max period)
            collateral_lock_amount: None,
            collateral_lock_until: None,
        },
    ];

    let (bps, fixed, period) = strictest_quorum_limits(&members);
    // Most restrictive: highest min_bps, highest min_fixed, lowest max_period
    assert_eq!(bps, Some(100));
    assert_eq!(fixed, Some(5000));
    assert_eq!(period, Some(2016));
}

#[test]
fn strictest_limits_with_none_values() {
    let members = vec![
        QuorumMember {
            pubkey: test_pubkey_2(),
            ledger_id: String::new(),
            min_fee_bps: Some(50),
            min_fee_fixed: None,
            max_fee_period: Some(2016),
            collateral_lock_amount: None,
            collateral_lock_until: None,
        },
        QuorumMember {
            pubkey: test_pubkey_3(),
            ledger_id: String::new(),
            min_fee_bps: None,
            min_fee_fixed: Some(1000),
            max_fee_period: None,
            collateral_lock_amount: None,
            collateral_lock_until: None,
        },
    ];

    let (bps, fixed, period) = strictest_quorum_limits(&members);
    // None means no constraint from that member
    assert_eq!(bps, Some(50));
    assert_eq!(fixed, Some(1000));
    assert_eq!(period, Some(2016));
}

#[test]
fn strictest_limits_all_none() {
    let members = vec![
        QuorumMember {
            pubkey: test_pubkey_2(),
            ledger_id: String::new(),
            min_fee_bps: None,
            min_fee_fixed: None,
            max_fee_period: None,
            collateral_lock_amount: None,
            collateral_lock_until: None,
        },
    ];

    let (bps, fixed, period) = strictest_quorum_limits(&members);
    assert_eq!(bps, None);
    assert_eq!(fixed, None);
    assert_eq!(period, None);
}

// =========================================================================
// Fee validation against quorum limits
// =========================================================================

#[test]
fn fees_meeting_all_limits_pass() {
    let members = vec![QuorumMember {
        pubkey: test_pubkey_2(),
        ledger_id: String::new(),
        min_fee_bps: Some(50),
        min_fee_fixed: Some(1000),
        max_fee_period: Some(2016),
        collateral_lock_amount: None,
        collateral_lock_until: None,
    }];

    let fees = FeeStructure {
        annualized_bps: 100, // above 50 min
        annualized_fixed: 5000, // above 1000 min
        frequency_blocks: 2016, // equal to max
    };

    assert!(fees_meet_quorum_limits(&fees, &members).is_ok());
}

#[test]
fn fees_below_min_bps_rejected() {
    let members = vec![QuorumMember {
        pubkey: test_pubkey_2(),
        ledger_id: String::new(),
        min_fee_bps: Some(100),
        min_fee_fixed: None,
        max_fee_period: None,
        collateral_lock_amount: None,
        collateral_lock_until: None,
    }];

    let fees = FeeStructure {
        annualized_bps: 50, // below 100 min
        annualized_fixed: 10_000,
        frequency_blocks: 2016,
    };

    let err = fees_meet_quorum_limits(&fees, &members).unwrap_err();
    assert!(err.contains("bps"), "error should mention bps: {}", err);
}

#[test]
fn fees_below_min_fixed_rejected() {
    let members = vec![QuorumMember {
        pubkey: test_pubkey_2(),
        ledger_id: String::new(),
        min_fee_bps: None,
        min_fee_fixed: Some(5000),
        max_fee_period: None,
        collateral_lock_amount: None,
        collateral_lock_until: None,
    }];

    let fees = FeeStructure {
        annualized_bps: 100,
        annualized_fixed: 1000, // below 5000 min
        frequency_blocks: 2016,
    };

    let err = fees_meet_quorum_limits(&fees, &members).unwrap_err();
    assert!(err.contains("Fixed fee"), "error should mention fixed fee: {}", err);
}

#[test]
fn fees_exceeding_max_period_rejected() {
    let members = vec![QuorumMember {
        pubkey: test_pubkey_2(),
        ledger_id: String::new(),
        min_fee_bps: None,
        min_fee_fixed: None,
        max_fee_period: Some(2016),
        collateral_lock_amount: None,
        collateral_lock_until: None,
    }];

    let fees = FeeStructure {
        annualized_bps: 100,
        annualized_fixed: 5000,
        frequency_blocks: 4032, // exceeds 2016 max
    };

    let err = fees_meet_quorum_limits(&fees, &members).unwrap_err();
    assert!(err.contains("period"), "error should mention period: {}", err);
}

#[test]
fn fees_with_no_quorum_limits_always_pass() {
    let members = vec![QuorumMember {
        pubkey: test_pubkey_2(),
        ledger_id: String::new(),
        min_fee_bps: None,
        min_fee_fixed: None,
        max_fee_period: None,
        collateral_lock_amount: None,
        collateral_lock_until: None,
    }];

    // Even zero fees pass when member has no limits
    let fees = FeeStructure {
        annualized_bps: 0,
        annualized_fixed: 0,
        frequency_blocks: 100_000,
    };

    assert!(fees_meet_quorum_limits(&fees, &members).is_ok());
}

#[test]
fn fees_must_satisfy_strictest_member() {
    let members = vec![
        QuorumMember {
            pubkey: test_pubkey_2(),
            ledger_id: String::new(),
            min_fee_bps: Some(50),
            min_fee_fixed: None,
            max_fee_period: None,
            collateral_lock_amount: None,
            collateral_lock_until: None,
        },
        QuorumMember {
            pubkey: test_pubkey_3(),
            ledger_id: String::new(),
            min_fee_bps: Some(200), // strictest
            min_fee_fixed: None,
            max_fee_period: None,
            collateral_lock_amount: None,
            collateral_lock_until: None,
        },
    ];

    // 100 bps meets member 1 (50) but not member 2 (200)
    let fees = FeeStructure {
        annualized_bps: 100,
        annualized_fixed: 10_000,
        frequency_blocks: 2016,
    };

    let err = fees_meet_quorum_limits(&fees, &members).unwrap_err();
    assert!(err.contains("200"), "error should mention strictest limit: {}", err);

    // 200 bps meets both
    let fees_ok = FeeStructure {
        annualized_bps: 200,
        annualized_fixed: 10_000,
        frequency_blocks: 2016,
    };

    assert!(fees_meet_quorum_limits(&fees_ok, &members).is_ok());
}

// =========================================================================
// End-to-end: add members with limits, open deposit, verify limits applied
// =========================================================================

#[test]
fn deposit_open_on_ledger_with_quorum_fee_limits() {
    let mut ledger = make_ledger();

    // Add two quorum members with different fee requirements
    add_member(&mut ledger, test_pubkey_2(), Some(50), Some(1000), Some(4032));
    add_member(&mut ledger, test_pubkey_3(), Some(100), None, Some(2016));

    assert_eq!(ledger.state.quorum_members.len(), 2);

    // Verify the strictest limits
    let (bps, fixed, period) = strictest_quorum_limits(&ledger.state.quorum_members);
    assert_eq!(bps, Some(100));  // strictest: 100 > 50
    assert_eq!(fixed, Some(1000)); // only member 1 has a fixed limit
    assert_eq!(period, Some(2016)); // strictest: 2016 < 4032

    // Open a deposit with fees that meet limits
    let good_fees = FeeStructure {
        annualized_bps: 150,
        annualized_fixed: 5000,
        frequency_blocks: 2016,
    };
    assert!(fees_meet_quorum_limits(&good_fees, &ledger.state.quorum_members).is_ok());

    let did = compute_deposit_id("pk(good_deposit)");
    ledger
        .apply_state_changes(&LedgerOperation::DepositOpen {
            deposit_id: did,
            descriptor: "pk(good_deposit)".to_string(),
            fees: Some(good_fees),
            transfer_fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
            is_collateral: false,
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
        })
        .unwrap();

    assert!(ledger.state.deposits.contains_key(&did));

    // A deposit with fees below limits should be rejected (by the co-signer)
    let bad_fees = FeeStructure {
        annualized_bps: 25, // below 100 minimum
        annualized_fixed: 500, // below 1000 minimum
        frequency_blocks: 8064, // above 2016 maximum
    };
    let err = fees_meet_quorum_limits(&bad_fees, &ledger.state.quorum_members).unwrap_err();
    assert!(err.contains("bps"), "first failure should be bps: {}", err);
}

// =========================================================================
// QuorumMember struct TLV roundtrip with fee limits
// =========================================================================

#[test]
fn quorum_member_struct_fee_limits_survive_json_roundtrip() {
    let member = QuorumMember {
        pubkey: test_pubkey_2(),
        ledger_id: "test_ledger".to_string(),
        min_fee_bps: Some(75),
        min_fee_fixed: Some(2500),
        max_fee_period: Some(1008),
        collateral_lock_amount: None,
        collateral_lock_until: None,
    };

    let json = serde_json::to_string(&member).unwrap();
    let decoded: QuorumMember = serde_json::from_str(&json).unwrap();

    assert_eq!(member, decoded);
    assert_eq!(decoded.min_fee_bps, Some(75));
    assert_eq!(decoded.min_fee_fixed, Some(2500));
    assert_eq!(decoded.max_fee_period, Some(1008));
}

#[test]
fn quorum_member_struct_no_limits_json_roundtrip() {
    let member = QuorumMember {
        pubkey: test_pubkey_2(),
        ledger_id: "test_ledger".to_string(),
        min_fee_bps: None,
        min_fee_fixed: None,
        max_fee_period: None,
        collateral_lock_amount: None,
        collateral_lock_until: None,
    };

    let json = serde_json::to_string(&member).unwrap();
    let decoded: QuorumMember = serde_json::from_str(&json).unwrap();

    assert_eq!(member, decoded);
}

// =========================================================================
// Collateral obligation limits
// =========================================================================

/// Compute the maximum obligations allowed based on quorum collateral commitments.
/// Returns None if no members have commitments (no limit).
fn max_obligations(members: &[QuorumMember]) -> Option<u64> {
    members.iter()
        .filter_map(|m| m.collateral_lock_amount)
        .min()
        .map(|min_collateral| min_collateral.saturating_mul(2))
}

/// Check if current obligations + additional would exceed the limit.
fn check_obligation_limit(
    members: &[QuorumMember],
    current_obligations: u64,
    additional: u64,
) -> Result<(), String> {
    if let Some(max) = max_obligations(members) {
        let total = current_obligations.saturating_add(additional);
        if total > max {
            return Err(format!(
                "Would exceed limit: {} + {} = {} > {} (2x smallest collateral)",
                current_obligations, additional, total, max
            ));
        }
    }
    Ok(())
}

#[test]
fn obligation_limit_no_members_no_limit() {
    let members: Vec<QuorumMember> = vec![];
    assert!(check_obligation_limit(&members, 1_000_000, 1_000_000).is_ok());
}

#[test]
fn obligation_limit_no_collateral_commitments_no_limit() {
    let members = vec![QuorumMember {
        pubkey: test_pubkey_2(),
        ledger_id: String::new(),
        min_fee_bps: None, min_fee_fixed: None, max_fee_period: None,
        collateral_lock_amount: None, collateral_lock_until: None,
    }];
    assert!(check_obligation_limit(&members, 1_000_000, 1_000_000).is_ok());
}

#[test]
fn obligation_within_limit_passes() {
    let members = vec![QuorumMember {
        pubkey: test_pubkey_2(),
        ledger_id: String::new(),
        min_fee_bps: None, min_fee_fixed: None, max_fee_period: None,
        collateral_lock_amount: Some(100_000), // 2x = 200_000 max
        collateral_lock_until: Some(10000),
    }];
    // 50k existing + 100k new = 150k < 200k limit
    assert!(check_obligation_limit(&members, 50_000, 100_000).is_ok());
}

#[test]
fn obligation_at_limit_passes() {
    let members = vec![QuorumMember {
        pubkey: test_pubkey_2(),
        ledger_id: String::new(),
        min_fee_bps: None, min_fee_fixed: None, max_fee_period: None,
        collateral_lock_amount: Some(100_000),
        collateral_lock_until: Some(10000),
    }];
    // 100k + 100k = 200k == 200k limit (exactly at limit, passes)
    assert!(check_obligation_limit(&members, 100_000, 100_000).is_ok());
}

#[test]
fn obligation_exceeding_limit_rejected() {
    let members = vec![QuorumMember {
        pubkey: test_pubkey_2(),
        ledger_id: String::new(),
        min_fee_bps: None, min_fee_fixed: None, max_fee_period: None,
        collateral_lock_amount: Some(100_000),
        collateral_lock_until: Some(10000),
    }];
    // 100k + 100k + 1 > 200k limit
    let err = check_obligation_limit(&members, 100_001, 100_000).unwrap_err();
    assert!(err.contains("exceed"), "{}", err);
}

#[test]
fn obligation_limit_uses_smallest_member() {
    let members = vec![
        QuorumMember {
            pubkey: test_pubkey_2(),
            ledger_id: String::new(),
            min_fee_bps: None, min_fee_fixed: None, max_fee_period: None,
            collateral_lock_amount: Some(500_000), // large
            collateral_lock_until: Some(10000),
        },
        QuorumMember {
            pubkey: test_pubkey_3(),
            ledger_id: String::new(),
            min_fee_bps: None, min_fee_fixed: None, max_fee_period: None,
            collateral_lock_amount: Some(50_000), // small — this is the bottleneck
            collateral_lock_until: Some(10000),
        },
    ];
    // Max = 2 * 50_000 = 100_000
    assert!(check_obligation_limit(&members, 0, 100_000).is_ok());
    assert!(check_obligation_limit(&members, 0, 100_001).is_err());
}

#[test]
fn obligation_limit_mixed_some_none() {
    let members = vec![
        QuorumMember {
            pubkey: test_pubkey_2(),
            ledger_id: String::new(),
            min_fee_bps: None, min_fee_fixed: None, max_fee_period: None,
            collateral_lock_amount: Some(100_000),
            collateral_lock_until: Some(10000),
        },
        QuorumMember {
            pubkey: test_pubkey_3(),
            ledger_id: String::new(),
            min_fee_bps: None, min_fee_fixed: None, max_fee_period: None,
            collateral_lock_amount: None, // no commitment
            collateral_lock_until: None,
        },
    ];
    // Only one member has a commitment: limit = 2 * 100_000 = 200_000
    assert!(check_obligation_limit(&members, 0, 200_000).is_ok());
    assert!(check_obligation_limit(&members, 0, 200_001).is_err());
}

// =========================================================================
// Membership duration limited by shortest collateral lock
// =========================================================================

/// Compute maximum membership duration from collateral lock times.
fn max_membership_block(members: &[QuorumMember]) -> Option<u32> {
    members.iter()
        .filter_map(|m| m.collateral_lock_until)
        .min()
}

#[test]
fn membership_duration_limited_by_shortest_lock() {
    let members = vec![
        QuorumMember {
            pubkey: test_pubkey_2(),
            ledger_id: String::new(),
            min_fee_bps: None, min_fee_fixed: None, max_fee_period: None,
            collateral_lock_amount: Some(100_000),
            collateral_lock_until: Some(50_000), // locks until block 50k
        },
        QuorumMember {
            pubkey: test_pubkey_3(),
            ledger_id: String::new(),
            min_fee_bps: None, min_fee_fixed: None, max_fee_period: None,
            collateral_lock_amount: Some(100_000),
            collateral_lock_until: Some(30_000), // locks until block 30k — shortest
        },
    ];

    assert_eq!(max_membership_block(&members), Some(30_000));
}

#[test]
fn membership_duration_no_locks_no_limit() {
    let members = vec![QuorumMember {
        pubkey: test_pubkey_2(),
        ledger_id: String::new(),
        min_fee_bps: None, min_fee_fixed: None, max_fee_period: None,
        collateral_lock_amount: None,
        collateral_lock_until: None,
    }];
    assert_eq!(max_membership_block(&members), None);
}
