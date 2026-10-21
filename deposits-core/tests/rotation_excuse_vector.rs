//! DEP-06 proof 10 "Recorded rotation", against the vector cl-deposits generates
//! (tests/vectors/rotation_excuse.txt): a spend is a recorded rotation iff a `QuorumBegin` signed
//! by the ledger's operator, reachable from the governing `QuorumBegin` by `previous_hash` links at
//! consecutive sequences, names it. The updates are what a judge gathered from its replica and the
//! relay together: a dead-end variant, a member's `QuorumBegin`, an unlinked one, a skipped
//! sequence and a forged signature sit beside the real chain.
use deposits_core::types::SignedLedgerUpdate;
use deposits_core::vault_spend::rotation_excused;
use deposits_core::TlvDecode;

#[test]
fn rotation_excuse_matches_cl() {
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    let mut governing = 0u64;
    let mut cases = Vec::new();
    for line in include_str!("vectors/rotation_excuse.txt").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let w: Vec<&str> = line.split(' ').collect();
        match w[0] {
            "update" => {
                updates.push(SignedLedgerUpdate::tlv_decode(&hex::decode(w[1]).unwrap()).unwrap())
            }
            "governing" => governing = w[1].parse().unwrap(),
            "case" => cases.push((w[1].to_string(), w[2] == "1", w[3].to_string())),
            _ => {}
        }
    }
    assert_eq!(cases.len(), 7);
    for (name, want, hex_txid) in &cases {
        let txid: [u8; 32] = hex::decode(hex_txid).unwrap().try_into().unwrap();
        assert_eq!(
            rotation_excused(&updates, governing, &txid),
            *want,
            "case {name}"
        );
        let mut rev = updates.clone();
        rev.reverse();
        assert_eq!(
            rotation_excused(&rev, governing, &txid),
            *want,
            "case {name}, reversed"
        );
    }
}
