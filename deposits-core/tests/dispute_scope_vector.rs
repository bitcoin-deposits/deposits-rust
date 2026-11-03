//! DEP-03 §"The dispute": `rotation_order::dispute_scope` against the shared vector
//! `deposits-protocol/tests/vectors/dispute_scope.txt` (cl-deposits passes the same file).

use deposits_core::messages::{LedgerOperation, QuorumMemberRef};
use deposits_core::rotation_order::dispute_scope;
use deposits_core::types::SignedLedgerUpdate;
use deposits_core::TlvEncode;

fn key(c: char) -> bitcoin::secp256k1::PublicKey {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&[c as u8; 32]).unwrap();
    bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
}

fn op_of(kind: &str, arg: Option<u64>) -> LedgerOperation {
    match kind {
        "open" => LedgerOperation::LedgerOpen {
            operator_id: key('o'),
            reserves_id: "r".into(),
            genesis_block: 0,
            reserves_amount: 1,
            collateral_amount: 1,
            protocol_version: None,
        },
        "qb" => LedgerOperation::QuorumBegin {
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
            reserves_id: "r".into(),
            spending_txid: [0; 32],
            new_outpoint_txid: [1; 32],
            new_outpoint_vout: 0,
            amount: 1,
            quorum_expiry: 1_000_000,
            ledger_hash: [0; 32],
            quorum_members: vec![QuorumMemberRef::pubkey_only(key('m'))],
            collateral_amount: 1,
            protocol_version: Some("cltv-offset-v2".into()),
        },
        "enter" => LedgerOperation::DisputeEnter {
            last_valid_sequence: arg.unwrap(),
            reason: "quorum_expired".into(),
            anchor_block_hash: None,
            anchor_block_height: None,
            fraud_proof_hash: None,
            fraud_proof: None,
        },
        _ => LedgerOperation::DisputeYield,
    }
}

fn update(who: char, seq: u64, op: &LedgerOperation) -> SignedLedgerUpdate {
    SignedLedgerUpdate {
        message: op.tlv_encode(),
        message_type: 1,
        operator_id: key(who),
        ledger_id: [9; 32],
        sequence_number: seq,
        previous_hash: [0; 32],
        content_hash: [0; 32],
        block_height: 0,
        block_hash: [1; 32],
        operator_signature: [0; 64],
        cosignatures: Vec::new(),
    }
}

#[test]
fn dispute_scope_vector() {
    let text = include_str!("../../deposits-protocol/tests/vectors/dispute_scope.txt");
    let (mut name, mut ups, mut cases) = (String::new(), Vec::new(), 0);
    let mut tags: Vec<(char, u64)> = Vec::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let w: Vec<&str> = line.split_whitespace().collect();
        match w[0] {
            "case" => {
                name = w[1].to_string();
                ups.clear();
                tags.clear();
            }
            "u" => {
                let who = w[1].chars().next().unwrap();
                let seq: u64 = w[2].parse().unwrap();
                ups.push(update(
                    who,
                    seq,
                    &op_of(w[3], w.get(4).map(|s| s.parse().unwrap())),
                ));
                tags.push((who, seq));
            }
            "expect" => {
                let want: Vec<String> = w[1..].iter().map(|s| s.to_string()).collect();
                let kept = dispute_scope(&ups);
                let got: Vec<String> = kept
                    .iter()
                    .map(|k| {
                        let i = ups.iter().position(|u| u == k).unwrap();
                        format!("{}:{}", tags[i].0, tags[i].1)
                    })
                    .collect();
                assert_eq!(got, want, "case {}", name);
                cases += 1;
            }
            _ => {}
        }
    }
    assert_eq!(cases, 5);
}
