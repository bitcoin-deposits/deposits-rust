//! DEP-20 §8.3: `UncreditedOnchainPayment` with migration evidence, against the vector
//! cl-deposits generates (tests/vectors/migration_proof.txt): the proof hash and the verdict
//! over the receiver's history, for several `proof_sequence` / `service_response_blocks`.
use deposits_core::fraud::{
    uncredited_migration_proof, verify_uncredited_migration, FraudEvidence, FraudProof,
    FraudProofType,
};
use deposits_core::types::SignedLedgerUpdate;
use deposits_core::TlvDecode;
use std::collections::HashMap;

#[test]
fn migration_proof_matches_cl() {
    let mut kv: HashMap<String, String> = HashMap::new();
    let mut history: Vec<SignedLedgerUpdate> = Vec::new();
    let mut blocks: HashMap<[u8; 32], u32> = HashMap::new();
    let mut checked = 0;
    let mut cl_json: Option<String> = None;
    for line in include_str!("vectors/migration_proof.txt").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let w: Vec<&str> = line.split(' ').collect();
        match w[0] {
            "update" => {
                history.push(SignedLedgerUpdate::tlv_decode(&hex::decode(w[1]).unwrap()).unwrap())
            }
            "block" => {
                blocks.insert(
                    hex::decode(w[1]).unwrap().try_into().unwrap(),
                    w[2].parse().unwrap(),
                );
            }
            "json" => cl_json = Some(line[5..].to_string()),
            "produce" => {
                let upto: u64 = w[1].parse().unwrap();
                let source = vec![
                    SignedLedgerUpdate::tlv_decode(&hex::decode(&kv["notice"]).unwrap()).unwrap(),
                    SignedLedgerUpdate::tlv_decode(&hex::decode(&kv["qb"]).unwrap()).unwrap(),
                ];
                let receiver: Vec<SignedLedgerUpdate> = history
                    .iter()
                    .filter(|u| u.sequence_number <= upto)
                    .cloned()
                    .collect();
                let confirmed = *blocks.iter().find(|(_, h)| **h == 150).unwrap().0;
                let p = uncredited_migration_proof(
                    &source,
                    &receiver,
                    confirmed,
                    150,
                    w[2].parse().unwrap(),
                );
                let got = p.map_or("none".to_string(), |p| match p.evidence {
                    FraudEvidence::UncreditedMigration { proof_sequence, .. } => {
                        proof_sequence.to_string()
                    }
                    _ => "other".into(),
                });
                assert_eq!(got, w[3], "{line}");
                checked += 1;
            }
            "proof" => {
                let proof = FraudProof {
                    proof_type: FraudProofType::UncreditedOnchainPayment,
                    accused: kv["accused"].clone(),
                    ledger_id: kv["ledger"].clone(),
                    evidence: FraudEvidence::UncreditedMigration {
                        source_notice_update: kv["notice"].clone(),
                        source_qb_update: kv["qb"].clone(),
                        confirmed_at_block_hash: *blocks
                            .iter()
                            .find(|(_, h)| **h == 150)
                            .unwrap()
                            .0,
                        proof_sequence: w[1].parse().unwrap(),
                        service_response_blocks: w[2].parse().unwrap(),
                    },
                };
                assert_eq!(hex::encode(proof.proof_hash()), w[6], "hash of {line}");
                assert!(
                    !proof.requires_embedding(),
                    "migration evidence is self-evident"
                );
                if let (Some(j), "11", "72") = (&cl_json, w[1], w[2]) {
                    let b: deposits_core::fraud::FraudBroadcast = serde_json::from_str(j).unwrap();
                    assert_eq!(
                        b.proof.proof_hash(),
                        proof.proof_hash(),
                        "cl's broadcast JSON"
                    );
                    b.verify_chain_structure().unwrap();
                    checked += 1;
                }
                let oracle = |b: &[u8; 32]| blocks.get(b).copied();
                let verdict = verify_uncredited_migration(&proof, &history, &oracle);
                assert_eq!(verdict.is_ok(), w[4] == "1", "{line}: {verdict:?}");
                checked += 1;
            }
            k => {
                kv.insert(k.to_string(), w[1].to_string());
            }
        }
    }
    assert_eq!(checked, 9);
}
