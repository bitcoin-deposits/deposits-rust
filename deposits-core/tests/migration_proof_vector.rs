//! DEP-20 §8.3: `UncreditedOnchainPayment` with migration evidence, against the vector
//! cl-deposits generates (tests/vectors/migration_proof.txt): the receiver's governing deadline,
//! the producer, cl's broadcast JSON, a forged carried deadline (ignored, so rejected), and the
//! proof hash and verdict at several proof updates.
use deposits_core::fraud::{
    governing_service_response_blocks, uncredited_migration_proof, verify_uncredited_migration,
    FraudBroadcast, FraudEvidence, FraudProof, FraudProofType,
};
use deposits_core::types::SignedLedgerUpdate;
use deposits_core::{TlvDecode, TlvEncode};
use std::collections::HashMap;

#[test]
fn migration_proof_matches_cl() {
    let mut kv: HashMap<String, String> = HashMap::new();
    let mut history: Vec<SignedLedgerUpdate> = Vec::new();
    let mut blocks: HashMap<[u8; 32], u32> = HashMap::new();
    let mut checked = 0;
    let dec = |h: &str| SignedLedgerUpdate::tlv_decode(&hex::decode(h).unwrap()).unwrap();
    for line in include_str!("vectors/migration_proof.txt").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let w: Vec<&str> = line.split(' ').collect();
        let confirmed = || *blocks.iter().find(|(_, h)| **h == 150).unwrap().0;
        match w[0] {
            "update" => history.push(dec(w[1])),
            "block" => {
                blocks.insert(
                    hex::decode(w[1]).unwrap().try_into().unwrap(),
                    w[2].parse().unwrap(),
                );
            }
            "terms" => {
                assert_eq!(
                    governing_service_response_blocks(&history, 5).to_string(),
                    w[1]
                );
                checked += 1;
            }
            "produce" => {
                let upto: u64 = w[1].parse().unwrap();
                let source = vec![dec(&kv["notice"]), dec(&kv["qb"])];
                let receiver: Vec<SignedLedgerUpdate> = history
                    .iter()
                    .filter(|u| u.sequence_number <= upto)
                    .cloned()
                    .collect();
                let p = uncredited_migration_proof(&source, &receiver, confirmed(), 150);
                let got = p.map_or("none".to_string(), |p| match p.evidence {
                    FraudEvidence::UncreditedMigration { proof_update, .. } => {
                        dec(&proof_update).sequence_number.to_string()
                    }
                    _ => "other".into(),
                });
                assert_eq!(got, w[2], "{line}");
                checked += 1;
            }
            "json" | "forged" => {
                let js = &line[w[0].len() + 1..line.find(" verdict ").unwrap_or(line.len())];
                let b: FraudBroadcast = serde_json::from_str(js).unwrap();
                assert!(!b.proof.requires_embedding());
                b.verify_chain_structure().unwrap();
                if w[0] == "forged" {
                    let oracle = |h: &[u8; 32]| blocks.get(h).copied();
                    let v = verify_uncredited_migration(&b.proof, &history, &oracle);
                    assert!(v.is_err(), "a carried deadline must be ignored: {v:?}");
                    assert_eq!(*w.last().unwrap(), "0");
                }
                checked += 1;
            }
            "proof" => {
                let seq: u64 = w[1].parse().unwrap();
                let pu = history.iter().find(|u| u.sequence_number == seq).unwrap();
                let proof = FraudProof {
                    proof_type: FraudProofType::UncreditedOnchainPayment,
                    accused: kv["accused"].clone(),
                    ledger_id: kv["ledger"].clone(),
                    evidence: FraudEvidence::UncreditedMigration {
                        source_notice_update: kv["notice"].clone(),
                        source_qb_update: kv["qb"].clone(),
                        proof_update: hex::encode(pu.tlv_encode()),
                        confirmed_at_block_hash: confirmed(),
                    },
                };
                assert_eq!(hex::encode(proof.proof_hash()), w[5], "hash of {line}");
                let oracle = |h: &[u8; 32]| blocks.get(h).copied();
                let verdict = verify_uncredited_migration(&proof, &history, &oracle);
                assert_eq!(verdict.is_ok(), w[3] == "1", "{line}: {verdict:?}");
                checked += 1;
            }
            k => {
                kv.insert(k.to_string(), w[1].to_string());
            }
        }
    }
    assert_eq!(checked, 9);
}
