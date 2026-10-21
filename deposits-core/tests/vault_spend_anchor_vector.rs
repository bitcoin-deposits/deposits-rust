//! DEP-06 proof 10 and §Spend challenge, against the vector cl-deposits generates
//! (tests/vectors/vault_spend_anchor.txt; inspect/rotation-test.lisp there). A vault spend
//! carries an anchor `H` or is theft on its face. Anchored, it is answered only by a
//! `QuorumBegin` whose `previous_hash` is `H`, signed by the operator, naming the spend among
//! its rungs and cosigned to the spend's tier threshold; decoys beside the real chain answer
//! nothing. Proved: unanchored on the witness alone; anchored only by a challenge that lapsed.

use deposits_core::tapscript_reserves::anchor_of;
use deposits_core::vault_spend::{rotation_answer, verify_unauthorized_vault_spend};
use deposits_protocol::fraud::FraudProof;
use deposits_protocol::tlv::TlvDecode;
use deposits_protocol::types::SignedLedgerUpdate;
use std::collections::HashMap;

struct Vector {
    updates: Vec<SignedLedgerUpdate>,
    blocks: HashMap<[u8; 32], u32>,
    spends: HashMap<String, bitcoin::Transaction>,
    answers: Vec<(String, String, String)>,
    proofs: Vec<(String, bool, String, String)>,
    governing: u64,
}

fn vector() -> Vector {
    let mut v = Vector {
        updates: vec![],
        blocks: HashMap::new(),
        spends: HashMap::new(),
        answers: vec![],
        proofs: vec![],
        governing: 0,
    };
    for line in include_str!("vectors/vault_spend_anchor.txt")
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let w: Vec<&str> = line.split(' ').collect();
        match w[0] {
            "governing" => v.governing = w[1].parse().unwrap(),
            "prevout" => {}
            "update" => v
                .updates
                .push(SignedLedgerUpdate::tlv_decode(&hex::decode(w[1]).unwrap()).unwrap()),
            "block" => {
                v.blocks.insert(hex::decode(w[1]).unwrap().try_into().unwrap(), w[2].parse().unwrap());
            }
            "spend" => {
                v.spends.insert(
                    w[1].to_string(),
                    bitcoin::consensus::deserialize(&hex::decode(w[2]).unwrap()).unwrap(),
                );
            }
            "answer" => v.answers.push((w[1].into(), w[2].into(), w[3].into())),
            "proof" => {
                let json = line.splitn(5, ' ').nth(4).unwrap().to_string();
                v.proofs.push((w[1].into(), w[2] == "1", w[3].into(), json));
            }
            k => panic!("unknown key {k}"),
        }
    }
    v
}

fn chain_hash(u: &SignedLedgerUpdate) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(u.compute_hash());
    h.update(u.operator_signature);
    hex::encode(h.finalize())
}

#[test]
fn answers_match_the_shared_vector() {
    let v = vector();
    assert_eq!((v.answers.len(), v.proofs.len()), (4, 8));
    let mut rev = v.updates.clone();
    rev.reverse();
    for (name, anchor, want) in &v.answers {
        let tx = &v.spends[name];
        let a = anchor_of(tx);
        assert_eq!(a.map(hex::encode).unwrap_or("none".into()), *anchor, "{name}: anchor");
        for updates in [&v.updates, &rev] {
            let got = a.and_then(|a| {
                rotation_answer(
                    updates,
                    &v.updates,
                    v.governing,
                    &a,
                    &bitcoin::hashes::Hash::to_byte_array(tx.compute_txid()),
                    0,
                )
            });
            assert_eq!(got.map(chain_hash).unwrap_or("none".into()), *want, "{name}: answered by");
        }
    }
}

#[test]
fn proofs_match_the_shared_vector() {
    let v = vector();
    let hob = |b: &[u8; 32]| v.blocks.get(b).copied();
    let answered = |txid: &[u8; 32], anchor: &[u8; 32], tier: usize| {
        rotation_answer(&v.updates, &v.updates, v.governing, anchor, txid, tier).is_some()
    };
    for (name, verdict, hash, json) in &v.proofs {
        let p: FraudProof = serde_json::from_str(json).unwrap();
        assert_eq!(hex::encode(p.proof_hash()), *hash, "{name}: proof hash");
        let got = verify_unauthorized_vault_spend(&p, &v.updates, &hob, &answered);
        assert_eq!(got.is_ok(), *verdict, "{name}: {:?}", got);
    }
}
