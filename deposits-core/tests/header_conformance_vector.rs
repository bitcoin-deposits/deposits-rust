//! DEP-02 §Block height and hash, against the vector cl-deposits generates
//! (tests/vectors/header_conformance.txt): heights never decrease along a chain (an equal height
//! is fine), every update names a block, and the hash is never judged against any chain (a
//! reorganised-out block is not a fault). Each case's verdict is whether a NonConformingUpdate
//! proof of its fault update verifies.
use deposits_core::dep16::Dep16Authorizer;
use deposits_core::fraud::{
    verify_non_conforming_update, FraudEvidence, FraudProof, FraudProofType,
};
use deposits_core::types::SignedLedgerUpdate;
use deposits_core::{TlvDecode, TlvEncode};

#[test]
fn header_conformance_matches_cl() {
    let dec = |h: &str| SignedLedgerUpdate::tlv_decode(&hex::decode(h).unwrap()).unwrap();
    let mut name = String::new();
    let mut history: Vec<SignedLedgerUpdate> = Vec::new();
    let mut fault: Option<SignedLedgerUpdate> = None;
    let mut checked = 0;
    for line in include_str!("vectors/header_conformance.txt").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let w: Vec<&str> = line.split(' ').collect();
        match w[0] {
            "case" => {
                name = w[1].to_string();
                history.clear();
            }
            "update" => history.push(dec(w[1])),
            "fault" => fault = Some(dec(w[1])),
            "verdict" => {
                let f = fault.take().unwrap();
                let proof = FraudProof {
                    proof_type: FraudProofType::NonConformingUpdate,
                    accused: hex::encode(f.operator_id.serialize()),
                    ledger_id: hex::encode(f.ledger_id),
                    evidence: FraudEvidence::NonConformingUpdate {
                        fault_sequence: f.sequence_number,
                        fault_update_hex: hex::encode(f.tlv_encode()),
                    },
                };
                let got = verify_non_conforming_update(&proof, &history, &Dep16Authorizer::new());
                assert_eq!(
                    if got.is_ok() { "1" } else { "0" },
                    w[1],
                    "case {name}: {got:?}"
                );
                checked += 1;
            }
            other => panic!("unknown line {other}"),
        }
    }
    assert_eq!(checked, 5);
}
