//! DEP-05/DEP-06: a ledger's governing `service_response_blocks`, against the vector cl-deposits
//! generates (tests/vectors/service_terms.txt): the largest value a seated member of the governing
//! `QuorumBegin` declared, 72 when none of them declared one or no `QuorumBegin` exists yet.
use deposits_core::fraud::governing_service_response_blocks;
use deposits_core::types::SignedLedgerUpdate;
use deposits_core::TlvDecode;

#[test]
fn service_terms_match_cl() {
    let mut history: Vec<SignedLedgerUpdate> = Vec::new();
    let mut checked = 0;
    for line in include_str!("vectors/service_terms.txt").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let w: Vec<&str> = line.split(' ').collect();
        match w[0] {
            "update" => {
                history.push(SignedLedgerUpdate::tlv_decode(&hex::decode(w[1]).unwrap()).unwrap())
            }
            "terms" => {
                assert_eq!(
                    governing_service_response_blocks(&history, w[1].parse().unwrap()).to_string(),
                    w[2],
                    "terms at {}",
                    w[1]
                );
                checked += 1;
            }
            other => panic!("unknown line {other}"),
        }
    }
    assert_eq!(checked, 6);
}
