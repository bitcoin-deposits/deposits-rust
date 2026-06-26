//! Tests for LedgerState conformance tracking.
//!
//! Verifies that apply_with_verifier detects violations (reserve backing,
//! witness verification) and that check_and_apply refuses non-conforming state.

use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::types::{
    compute_deposit_id, AllowAll, ConformanceViolation, FeeStructure, LedgerState,
    TransferFeeSchedule,
};

fn test_pubkey() -> bitcoin::secp256k1::PublicKey {
    use std::str::FromStr;
    bitcoin::secp256k1::PublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap()
}

fn make_state() -> LedgerState {
    let mut state = LedgerState::new(test_pubkey(), "bcrt1qtest".to_string(), 0);
    // Set reserves to 1 BTC (100_000_000 msats in protocol terms, but reserves_amount is sats)
    state.reserves_amount = 1_000_000;
    state
}

fn open_deposit(state: &LedgerState, descriptor: &str) -> LedgerState {
    let deposit_id = compute_deposit_id(descriptor);
    state
        .apply(&LedgerOperation::DepositOpen {
            deposit_id,
            descriptor: descriptor.to_string(),
            fees: Some(FeeStructure::default()),
            transfer_fees: Some(TransferFeeSchedule::default()),
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,

            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
        })
        .unwrap()
}

// ==========================================================================
// Reserve sufficiency
// ==========================================================================

#[test]
fn credit_within_reserves_is_conforming() {
    let state = make_state();
    let state = open_deposit(&state, "pk(aabbcc)");
    let deposit_id = compute_deposit_id("pk(aabbcc)");

    let (next, violations) = state
        .apply_with_verifier(
            &LedgerOperation::InvoiceCredit {
                payment_hash: [0xaa; 32],
                deposit_id,
                amount: 500_000, // half of reserves
                invoice_id: "test".to_string(),
                sequence_number: 1,
                wallet_authorization: None,
            },
            &AllowAll,
            0,
        )
        .unwrap();

    assert!(
        violations.is_empty(),
        "should be conforming: {:?}",
        violations
    );
    assert_eq!(next.deposits.get(&deposit_id).unwrap().balance, 500_000);
}

#[test]
fn credit_exceeding_reserves_is_non_conforming() {
    let state = make_state();
    let state = open_deposit(&state, "pk(aabbcc)");
    let deposit_id = compute_deposit_id("pk(aabbcc)");

    let (next, violations) = state
        .apply_with_verifier(
            &LedgerOperation::InvoiceCredit {
                payment_hash: [0xaa; 32],
                deposit_id,
                amount: 2_000_000, // double the reserves
                invoice_id: "test".to_string(),
                sequence_number: 1,
                wallet_authorization: None,
            },
            &AllowAll,
            0,
        )
        .unwrap();

    assert_eq!(violations.len(), 1);
    assert!(matches!(
        &violations[0],
        ConformanceViolation::InsufficientReserves {
            reserves: 1_000_000,
            obligations: 2_000_000
        }
    ));
    // State was still applied (for watchers)
    assert_eq!(next.deposits.get(&deposit_id).unwrap().balance, 2_000_000);
}

// `check_and_apply` was removed: the canonical pre-sign gate is
// `Ledger::append_operation` (via `check_speculative`), exercised in
// deposits-core integration tests rather than re-tested at this layer.
#[test]
#[ignore = "check_and_apply removed; coverage moved to deposits-core::append_operation"]
fn check_and_apply_refuses_non_conforming() {
}

#[test]
fn onchain_credit_exceeding_reserves_is_non_conforming() {
    let state = make_state();
    let state = open_deposit(&state, "pk(aabbcc)");
    let deposit_id = compute_deposit_id("pk(aabbcc)");

    let (_next, violations) = state
        .apply_with_verifier(
            &LedgerOperation::OnchainCredit {
                txid: [0x11; 32],
                vout: 0,
                deposit_id,
                amount: 5_000_000,
                funding_address: "bcrt1qfund".to_string(),
            },
            &AllowAll,
            0,
        )
        .unwrap();

    assert_eq!(violations.len(), 1);
    assert!(matches!(
        &violations[0],
        ConformanceViolation::InsufficientReserves { .. }
    ));
}

#[test]
fn multiple_credits_accumulate_correctly() {
    let state = make_state();
    let state = open_deposit(&state, "pk(aabbcc)");
    let deposit_id = compute_deposit_id("pk(aabbcc)");

    // First credit: 600k (within 1M reserves)
    let (state, violations) = state
        .apply_with_verifier(
            &LedgerOperation::InvoiceCredit {
                payment_hash: [0x01; 32],
                deposit_id,
                amount: 600_000,
                invoice_id: "inv1".to_string(),
                sequence_number: 1,
                wallet_authorization: None,
            },
            &AllowAll,
            0,
        )
        .unwrap();
    assert!(violations.is_empty());

    // Second credit: 600k (total 1.2M > 1M reserves)
    let (_state, violations) = state
        .apply_with_verifier(
            &LedgerOperation::InvoiceCredit {
                payment_hash: [0x02; 32],
                deposit_id,
                amount: 600_000,
                invoice_id: "inv2".to_string(),
                sequence_number: 2,
                wallet_authorization: None,
            },
            &AllowAll,
            0,
        )
        .unwrap();
    assert_eq!(violations.len(), 1);
    assert!(matches!(
        &violations[0],
        ConformanceViolation::InsufficientReserves {
            reserves: 1_000_000,
            obligations: 1_200_000,
        }
    ));
}

// ==========================================================================
// Operations that don't affect reserves are always conforming
// ==========================================================================

#[test]
fn deposit_open_is_conforming() {
    let state = make_state();
    let deposit_id = compute_deposit_id("pk(newdeposit)");

    let (_next, violations) = state
        .apply_with_verifier(
            &LedgerOperation::DepositOpen {
                deposit_id,
                descriptor: "pk(newdeposit)".to_string(),
                fees: Some(FeeStructure::default()),
                transfer_fees: None,
                payment_hash: None,
                invoice: None,
                cosigner_guarantee_signature: None,

                receive_requires_sig: false,
                fee_change_after_blocks: None,
                fee_change_notice_blocks: None,
                fee_change_limit_bps: None,
            },
            &AllowAll,
            0,
        )
        .unwrap();

    assert!(violations.is_empty());
}

#[test]
fn fee_collect_is_conforming() {
    let state = make_state();
    let state = open_deposit(&state, "pk(aabbcc)");
    let deposit_id = compute_deposit_id("pk(aabbcc)");

    // Credit some balance first
    let state = state
        .apply(&LedgerOperation::InvoiceCredit {
            payment_hash: [0xaa; 32],
            deposit_id,
            amount: 100_000,
            invoice_id: "test".to_string(),
            sequence_number: 1,
            wallet_authorization: None,
        })
        .unwrap();

    // Default `frequency_blocks` is 2016; `last_fee_assessment` is 0
    // on a freshly opened deposit, so the earliest conforming
    // FeeCollect lands at block 2016. Anything earlier emits a
    // FeeWindowNotElapsed violation (separate test case).
    let (_next, violations) = state
        .apply_with_verifier(
            &LedgerOperation::FeeCollect {
                deposit_id,
                amount: 1_000,
                block_height: 2016,
            },
            &AllowAll,
            0,
        )
        .unwrap();

    assert!(violations.is_empty());
}

#[test]
fn fee_collect_over_one_period_is_rejected() {
    // The block-0 fee-explosion guard at the consensus layer: even though the
    // deposit's last_fee_assessment is 0 (looks open since genesis), an operator
    // cannot sweep years of backlog — the amount must not exceed one period's
    // assessment. A patched cosigner rejects the over-large FeeCollect.
    let state = make_state();
    let state = open_deposit(&state, "pk(aabbcc)");
    let deposit_id = compute_deposit_id("pk(aabbcc)");

    let state = state
        .apply(&LedgerOperation::InvoiceCredit {
            payment_hash: [0xaa; 32],
            deposit_id,
            amount: 100_000,
            invoice_id: "test".to_string(),
            sequence_number: 1,
            wallet_authorization: None,
        })
        .unwrap();

    // Ask for ~18 years of backlog instead of the one capped period.
    let one_period = state.deposits.get(&deposit_id).unwrap().calculate_fees_due(2016);
    let greedy = one_period + 4_000_000;

    let fee_collect = |amount: u64| LedgerOperation::FeeCollect {
        deposit_id,
        amount,
        block_height: 955_504,
    };
    let exceeds = |vs: &[ConformanceViolation]| {
        vs.iter()
            .any(|v| matches!(v, ConformanceViolation::FeeExceedsAssessment { .. }))
    };

    // Dormant on `legacy` (DEP-18 version gate): the over-cap amount must NOT
    // be faulted, so an upgraded node never retroactively confiscates a
    // FeeCollect cosigned before the ledger adopts fee-cap-v3.
    let (_l, legacy_v) = state.apply_with_verifier(&fee_collect(greedy), &AllowAll, 0).unwrap();
    assert!(
        !exceeds(&legacy_v),
        "fee cap must be dormant on legacy, got {legacy_v:?}"
    );

    // Active on fee-cap-v3: the over-cap amount is rejected.
    let mut v3 = state.clone();
    v3.active_ruleset_name = "fee-cap-v3".to_string();
    let (_g, greedy_v) = v3.apply_with_verifier(&fee_collect(greedy), &AllowAll, 0).unwrap();
    assert!(exceeds(&greedy_v), "expected FeeExceedsAssessment, got {greedy_v:?}");

    // The exact one-period amount conforms even on fee-cap-v3.
    let due_now = v3.deposits.get(&deposit_id).unwrap().calculate_fees_due(955_504);
    let (_o, ok_v) = v3.apply_with_verifier(&fee_collect(due_now), &AllowAll, 0).unwrap();
    assert!(!exceeds(&ok_v), "one-period amount must conform, got {ok_v:?}");
}

#[test]
fn quorum_upgrade_same_family_applies() {
    // DEP-18: a QuorumUpgrade within the same reserves-cascade family
    // (cltv-offset-v2 -> fee-cap-v3) conforms and flips active_ruleset_name
    // off-chain, with no reserves change.
    let mut state = make_state();
    state.active_ruleset_name = "cltv-offset-v2".to_string();

    let (next, violations) = state
        .apply_with_verifier(
            &LedgerOperation::QuorumUpgrade {
                new_protocol_version: "fee-cap-v3".to_string(),
            },
            &AllowAll,
            0,
        )
        .unwrap();

    assert!(violations.is_empty(), "expected clean upgrade, got {violations:?}");
    assert_eq!(next.active_ruleset_name, "fee-cap-v3");
}

#[test]
fn quorum_upgrade_rejects_family_change_and_unknown() {
    // Changing the reserves-cascade family (legacy -> fee-cap-v3) must be
    // refused — that needs a QuorumBegin (on-chain UTXO change).
    let state = make_state(); // active_ruleset_name defaults to "legacy"
    let (_n, vs) = state
        .apply_with_verifier(
            &LedgerOperation::QuorumUpgrade {
                new_protocol_version: "fee-cap-v3".to_string(),
            },
            &AllowAll,
            0,
        )
        .unwrap();
    assert!(
        vs.iter()
            .any(|v| matches!(v, ConformanceViolation::RulesetFamilyMismatch { .. })),
        "expected RulesetFamilyMismatch, got {vs:?}"
    );

    // An unknown target ruleset is refused outright.
    let mut v2 = make_state();
    v2.active_ruleset_name = "cltv-offset-v2".to_string();
    let (_n2, vs2) = v2
        .apply_with_verifier(
            &LedgerOperation::QuorumUpgrade {
                new_protocol_version: "totally-bogus".to_string(),
            },
            &AllowAll,
            0,
        )
        .unwrap();
    assert!(
        vs2.iter()
            .any(|v| matches!(v, ConformanceViolation::UnknownRuleset { .. })),
        "expected UnknownRuleset, got {vs2:?}"
    );
}

#[test]
fn quorum_upgrade_codec_roundtrip() {
    use deposits_protocol::tlv::{TlvDecode, TlvEncode};
    let op = LedgerOperation::QuorumUpgrade {
        new_protocol_version: "fee-cap-v3".to_string(),
    };
    let bytes = op.tlv_encode();
    let back = LedgerOperation::tlv_decode(&bytes).unwrap();
    assert_eq!(op, back);
    assert_eq!(back.discriminant(), 45);
}
