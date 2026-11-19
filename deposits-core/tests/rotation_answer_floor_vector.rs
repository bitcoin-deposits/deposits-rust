//! DEP-06 rotation answer floor, against the shared vector cl-deposits ships
//! (tests/vectors/rotation_answer_floor.json; inspect/node-test.lisp "rotation answer floor" there).
//! The updates are the signet soak's own: ledger C (8b19a178), whose post-expiry rescue was planned
//! at vault tier 0 just before tier 1 opened and recorded after it, with the 3 cosignatures DEP-05
//! asks there, while its rung still spent tier 0 (5 of 8, operator included: a judge needs 4). No
//! judge accepts that QuorumBegin as the answer; the operator's lapsed challenge of its own rotation
//! proved all five signers (2026-11-19). An operator must not record such a QuorumBegin and a
//! member must not sign its rungs: both apply `answer_cosign_need`, the floor checked here.

use deposits_core::tapscript_reserves::anchor_of;
use deposits_core::vault_spend::{answer_floor, rotation_answer, tier_cosignatures};
use deposits_protocol::tlv::TlvDecode;
use deposits_protocol::types::SignedLedgerUpdate;

fn update(v: &serde_json::Value, k: &str) -> SignedLedgerUpdate {
    SignedLedgerUpdate::tlv_decode(&hex::decode(v[k].as_str().unwrap()).unwrap()).unwrap()
}

#[test]
fn signet_c_rescue_answers_nothing_below_the_floor() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("vectors/rotation_answer_floor.json")).unwrap();
    let e = &v["expect"];
    let open = update(&v, "ledger_open_hex");
    let gov = update(&v, "governing_quorum_begin_hex");
    let ans = update(&v, "answer_quorum_begin_hex");
    assert_eq!(gov.sequence_number, e["governing_seq"].as_u64().unwrap());
    assert_eq!(ans.sequence_number, e["answer_seq"].as_u64().unwrap());
    let spend: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&hex::decode(v["spend_tx_hex"].as_str().unwrap()).unwrap())
            .unwrap();
    let history = vec![open, gov.clone()];
    let gseq = gov.sequence_number;
    let tier = e["tier_index"].as_u64().unwrap() as usize;
    let (keys, need) = answer_floor(&history, gseq, tier).expect("the spent tier's floor");
    assert_eq!(keys.len() as u64, e["tier_keys"].as_u64().unwrap(), "its keys");
    assert_eq!(need as u64, e["needed_cosignatures"].as_u64().unwrap(), "cosignatures a judge needs");
    assert_eq!(
        tier_cosignatures(&ans, &keys) as u64,
        e["tier_cosignatures"].as_u64().unwrap(),
        "cosignatures the QuorumBegin carries by them"
    );
    let anchor = anchor_of(&spend).expect("an anchored spend");
    let txid = spend.compute_txid().to_byte_array();
    assert_eq!(ans.previous_hash, anchor, "it extends the anchor");
    assert_eq!(
        rotation_answer(std::slice::from_ref(&ans), &history, gseq, &anchor, &txid, tier).is_some(),
        e["answers"].as_bool().unwrap(),
        "no judge accepts it at the tier the rung spent"
    );
    // At tier 1, whose floor its cosignatures reach, the same QuorumBegin would answer.
    let (k1, n1) = answer_floor(&history, gseq, 1).unwrap();
    assert!(tier_cosignatures(&ans, &k1) >= n1);
    assert!(rotation_answer(std::slice::from_ref(&ans), &history, gseq, &anchor, &txid, 1).is_some());
}

use bitcoin::hashes::Hash;
