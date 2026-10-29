//! DEP-05 §"Born expired": a QuorumBegin whose quorum_expiry is at or below its own signed
//! block_height is refused by the author (staging) and by every cosigner. The arithmetic is
//! pinned by the vector shared with cl-deposits (deposits-protocol/tests/vectors/quorum_expiry.json).

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use deposits_core::ledger::Ledger;
use deposits_core::messages::{LedgerOperation, QuorumMemberRef};

fn pk(i: u8) -> PublicKey {
    PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[i; 32]).unwrap())
}

fn qb(expiry: u32) -> LedgerOperation {
    qb_under(expiry, "anchor-ladder-v5")
}

fn qb_under(expiry: u32, ruleset: &str) -> LedgerOperation {
    LedgerOperation::QuorumBegin {
        reserves_id: "x".into(),
        spending_txid: [0; 32],
        new_outpoint_txid: [0; 32],
        new_outpoint_vout: 0,
        amount: 0,
        quorum_expiry: expiry,
        ledger_hash: [0; 32],
        quorum_members: [2u8, 3, 4]
            .iter()
            .map(|i| QuorumMemberRef::new(pk(*i), String::new()))
            .collect(),
        collateral_amount: 0,
        protocol_version: Some(ruleset.into()),
        exit_cutoff_height: None,
        exit_outputs: Vec::new(),
        splice_in_outpoint: None,
        splice_in_amount: None,
        reference_feerate: None,
        dormancy_outputs: Vec::new(),
        migration_manifest: Vec::new(),
        migration_receiver: None,
        migration_vout: None,
        consumed_notice: None,
        rotation_rungs: vec![],
    }
}

#[test]
fn a_quorum_born_expired_is_refused() {
    let ledger = Ledger::new_as_operator(pk(1), "x".into(), 0);
    // DEP-18: a rule of anchor-ladder-v5. A QuorumBegin naming an earlier ruleset is never
    // judged by it (the soak's own 2026-10-24 rotations, re-applied, were convicted by it).
    assert!(ledger
        .check_quorum_begin_at(&qb_under(7181, "cltv-offset-v2"), 9341)
        .is_ok());
    // Signet soak, 2026-10-28: a rotation at height 9341 to the members' stale 7181.
    let err = ledger.check_quorum_begin_at(&qb(7181), 9341).unwrap_err();
    assert!(
        err.to_string().contains("quorum_expiry_not_after_block"),
        "{}",
        err
    );
    assert!(
        ledger.check_quorum_begin_at(&qb(9341), 9341).is_err(),
        "at the block is already lapsed"
    );
    assert!(
        ledger.check_quorum_begin_at(&qb(9342), 9341).is_ok(),
        "one block after is the earliest"
    );
    // An unsigned header (height 0) judges nothing.
    assert!(ledger.check_quorum_begin_at(&qb(1), 0).is_ok());
    // Other operations are not QuorumBegins.
    let open = LedgerOperation::LedgerOpen {
        operator_id: pk(1),
        reserves_id: "x".into(),
        genesis_block: 0,
        reserves_amount: 0,
        collateral_amount: 0,
        protocol_version: None,
    };
    assert!(ledger.check_quorum_begin_at(&open, 9341).is_ok());
}
