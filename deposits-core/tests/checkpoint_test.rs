//! Checkpoints are made by replay, never copied from the live state (Ledger::verify_checkpoint).
//! A live state that went wrong (as a double apply would make it) is caught at the next
//! checkpoint and replaced by the replay; nobody is accused.

use deposits_core::ledger::{CheckpointOutcome, Ledger};
use deposits_core::messages::LedgerOperation;
use deposits_core::types::{compute_deposit_id, FeeStructure};

fn fixed_pubkey() -> bitcoin::secp256k1::PublicKey {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
    bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
}

fn ledger_with(n: u64) -> (Ledger, [u8; 16]) {
    let op = fixed_pubkey();
    let mut ledger = Ledger::new_as_operator(op, hex::encode(op.serialize()), 0);
    ledger
        .append_operation_with_block(
            LedgerOperation::LedgerOpen {
                operator_id: op,
                reserves_id: hex::encode(op.serialize()),
                genesis_block: 0,
                reserves_amount: u64::MAX / 4,
                collateral_amount: 0,
                protocol_version: None,
            },
            0,
            [0u8; 32],
        )
        .unwrap();
    ledger.finalize_chain_hash();
    let descriptor = format!("pk({})", hex::encode(op.serialize()));
    let deposit_id = compute_deposit_id(&descriptor);
    ledger
        .append_operation_with_block(
            LedgerOperation::DepositOpen {
                deposit_id,
                descriptor,
                fees: Some(FeeStructure::default()),
                transfer_fees: None,
                payment_hash: None,
                invoice: None,
                cosigner_guarantee_signature: None,
                receive_requires_sig: false,
                fee_change_after_blocks: None,
                fee_change_notice_blocks: None,
                fee_change_limit_bps: None,
                commitment: None,
            },
            0,
            [0u8; 32],
        )
        .unwrap();
    ledger.finalize_chain_hash();
    for i in 0..n {
        ledger
            .append_operation_with_block(
                LedgerOperation::OnchainCredit {
                    txid: {
                        let mut t = [0u8; 32];
                        t[..8].copy_from_slice(&i.to_le_bytes());
                        t
                    },
                    vout: 0,
                    deposit_id,
                    amount: 1000,
                    funding_address: "bcrt1qfund".to_string(),
                    commitment: None,
                },
                1,
                [1u8; 32],
            )
            .unwrap();
        ledger.finalize_chain_hash();
    }
    (ledger, deposit_id)
}

#[test]
fn a_clean_checkpoint_agrees_with_the_live_state() {
    let (mut l, _) = ledger_with(6); // tip seq 7
    assert_eq!(l.verify_checkpoint(7), CheckpointOutcome::Taken);
    assert_eq!(l.verified_checkpoint.as_ref().unwrap().seq, 7);
    assert_eq!(
        l.verify_checkpoint(7),
        CheckpointOutcome::NotDue,
        "already taken there"
    );
}

#[test]
fn a_corrupted_live_state_is_replaced_by_the_replay() {
    let (mut l, dep) = ledger_with(6);
    assert_eq!(l.verify_checkpoint(7), CheckpointOutcome::Taken);
    let (mut l2, _) = ledger_with(13); // tip seq 14
    l2.verified_checkpoint = l.verified_checkpoint.take();
    let right = l2.state.deposits.get(&dep).unwrap().balance;
    l2.state.deposits.get_mut(&dep).unwrap().balance += 7; // as a double apply would
    assert_eq!(l2.verify_checkpoint(7), CheckpointOutcome::Mismatch);
    assert_eq!(
        l2.state.deposits.get(&dep).unwrap().balance,
        right,
        "replaced by the replay"
    );
    assert_eq!(l2.verified_checkpoint.as_ref().unwrap().seq, 14);
}

#[test]
fn a_replica_repairs_from_its_checkpoint() {
    let (mut l, dep) = ledger_with(10);
    // a checkpoint at seq 7, replayed from genesis
    let mut probe = l.clone();
    probe.history.truncate(8);
    probe.state = {
        let mut s = deposits_core::fraud::genesis_state(&probe.history[0]).unwrap();
        for u in &probe.history {
            s.apply_update_in_place(u).unwrap();
        }
        s
    };
    assert_eq!(probe.verify_checkpoint(7), CheckpointOutcome::Taken);
    l.verified_checkpoint = probe.verified_checkpoint.clone();
    let right = l.state.deposits.get(&dep).unwrap().balance;
    l.state.deposits.get_mut(&dep).unwrap().balance += 7;
    assert_eq!(
        l.repair_from_checkpoint().unwrap(),
        4,
        "seq 8..=11 replayed"
    );
    assert_eq!(l.state.deposits.get(&dep).unwrap().balance, right);
}

#[test]
fn with_no_replayable_base_the_first_checkpoint_is_the_live_state() {
    let (mut l, _) = ledger_with(6);
    l.history.drain(..3); // a compacted log: history starts at seq 3
    assert!(matches!(
        l.verify_checkpoint(7),
        CheckpointOutcome::Bootstrapped(_)
    ));
    assert!(l.verified_checkpoint.as_ref().unwrap().bootstrapped);
}
