//! DisputeDereliction (DEP-19 §6, FINDINGS D1): the shared vector cl-deposits
//! writes from its node gate (`inspect/node-test.lisp`, CL_DEPOSITS_WRITE_VECTORS=1).
//! Every case must get the verdict cl recorded and hash as cl hashed it: a real
//! report verifies; an invented original hash, an invented original proof, an
//! outsider's own disclosure (old block, carried window 0), a carried window of
//! 0 with the member still inside its own window, an unseated accused, and a
//! member that disputed within its window are all rejected.

use deposits_core::dep16::Dep16Authorizer;
use deposits_core::fraud::{
    verify_fraud_evidence, BlockOracle, FraudEvidence, FraudProof, LedgerProvider,
};
use deposits_core::types::SignedLedgerUpdate;
use deposits_core::TlvDecode;
use std::collections::HashMap;

struct Oracle(HashMap<[u8; 32], u32>);
impl BlockOracle for Oracle {
    fn confirms(&self, hash: &[u8; 32]) -> Option<u32> {
        self.0.get(hash).copied()
    }
}

struct Ledgers(HashMap<String, Vec<SignedLedgerUpdate>>);
impl LedgerProvider for Ledgers {
    fn ledger_history(&self, ledger_id: &str) -> Option<Vec<SignedLedgerUpdate>> {
        self.0.get(ledger_id).cloned()
    }
}

fn decode(hex_str: &serde_json::Value) -> SignedLedgerUpdate {
    SignedLedgerUpdate::tlv_decode(&hex::decode(hex_str.as_str().unwrap()).unwrap()).unwrap()
}

#[test]
fn every_case_matches_cl() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("vectors/dereliction.json")).unwrap();
    let blocks = v["blocks"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, h)| {
            (
                <[u8; 32]>::try_from(hex::decode(k).unwrap()).unwrap(),
                h.as_u64().unwrap() as u32,
            )
        })
        .collect();
    let oracle = Oracle(blocks);
    let defrauded: Vec<SignedLedgerUpdate> = v["defrauded_updates"]
        .as_array()
        .unwrap()
        .iter()
        .map(decode)
        .collect();
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let proof: FraudProof = serde_json::from_value(c["proof"].clone()).unwrap();
        assert_eq!(
            hex::encode(proof.proof_hash()),
            c["proof_hash"].as_str().unwrap(),
            "{name}: proof hash"
        );
        let FraudEvidence::DisputeDereliction { original_proof, .. } = &proof.evidence else {
            panic!("{name}: not a dereliction");
        };
        let mut m = HashMap::new();
        m.insert(
            proof.ledger_id.clone(),
            c["member_ledger"]
                .as_array()
                .unwrap()
                .iter()
                .map(decode)
                .collect(),
        );
        m.insert(original_proof.ledger_id.clone(), defrauded.clone());
        let got = verify_fraud_evidence(&proof, &Ledgers(m), &oracle, &Dep16Authorizer::new());
        let want_ok = c["expect"].as_str().unwrap() == "ok";
        assert_eq!(got.is_ok(), want_ok, "{name}: {got:?}");
    }
}
