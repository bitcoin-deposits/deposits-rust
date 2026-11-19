//! DEP-06 rotation answers, against the shared vector cl-deposits ships
//! (tests/vectors/rotation_answer_floor.json; inspect/node-test.lisp "rotation answer: the signet C
//! rescue ..." there). The updates are the signet soak's own: ledger C (8b19a178), whose post-expiry
//! rescue was planned at vault tier 0 just before tier 1 opened and recorded after it (height 8287,
//! lifecycle tier 1, where the ledger required 3 of its 7 members' cosignatures and it carries 3),
//! while its rung 2653505d still spent tier 0 (5 of 8, operator included: the tier floor is 4).
//! By the tier floor no judge accepts it; by `strict-lottery-v8`'s recorded-threshold answer (ruled
//! 2026-11-19) it answers. The negative is `synthetic`: the same operations re-signed with test keys, where 3 member cosignatures answer and 2 do not.

use deposits_core::tapscript_reserves::anchor_of;
use deposits_core::vault_spend::{
    answer_floor, recorded_threshold_met, rotation_answer, tier_cosignatures,
};
use deposits_protocol::cosign_threshold::establishment_requirement;
use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::tlv::TlvDecode;
use deposits_protocol::types::SignedLedgerUpdate;

fn update(v: &serde_json::Value, k: &str) -> SignedLedgerUpdate {
    SignedLedgerUpdate::tlv_decode(&hex::decode(v[k].as_str().unwrap()).unwrap()).unwrap()
}

#[test]
fn signet_c_rescue_answers_by_its_recorded_threshold() {
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

    // The tier floor: not met.
    let (keys, need) = answer_floor(&history, gseq, tier).expect("the spent tier's floor");
    assert_eq!(
        keys.len() as u64,
        e["tier_keys"].as_u64().unwrap(),
        "its keys"
    );
    assert_eq!(
        need as u64,
        e["needed_cosignatures"].as_u64().unwrap(),
        "cosignatures the tier floor needs"
    );
    assert_eq!(
        tier_cosignatures(&ans, &keys) as u64,
        e["tier_cosignatures"].as_u64().unwrap(),
        "cosignatures the QuorumBegin carries by them"
    );
    assert_eq!(
        tier_cosignatures(&ans, &keys) >= need,
        e["answers_by_tier_floor"].as_bool().unwrap()
    );

    // The ledger's own threshold where it was recorded: met.
    let LedgerOperation::QuorumBegin {
        quorum_members,
        quorum_expiry,
        protocol_version,
        ..
    } = LedgerOperation::tlv_decode(&gov.message).unwrap()
    else {
        panic!("governing update is a QuorumBegin")
    };
    assert_eq!(protocol_version.as_deref(), e["governing_ruleset"].as_str());
    let ans_op = LedgerOperation::tlv_decode(&ans.message).unwrap();
    let LedgerOperation::QuorumBegin {
        protocol_version: ans_rs,
        ..
    } = &ans_op
    else {
        panic!()
    };
    assert_eq!(ans_rs.as_deref(), e["answer_ruleset"].as_str());
    assert_eq!(
        ans.block_height as u64,
        e["answer_block_height"].as_u64().unwrap()
    );
    let members: Vec<_> = quorum_members
        .iter()
        .map(|m| m.pubkey.x_only_public_key().0)
        .collect();
    assert_eq!(
        establishment_requirement(
            members.len(),
            Some(quorum_expiry),
            protocol_version.as_deref().unwrap(),
            ans.block_height
        ) as u64,
        e["recorded_threshold"].as_u64().unwrap(),
        "the ledger's requirement at the recorded height (tier 1's minority)"
    );
    assert_eq!(
        tier_cosignatures(&ans, &members) as u64,
        e["member_cosignatures"].as_u64().unwrap()
    );
    assert!(recorded_threshold_met(&ans, &ans_op, &history, gseq));

    let anchor = anchor_of(&spend).expect("an anchored spend");
    let txid = spend.compute_txid().to_byte_array();
    assert_eq!(ans.previous_hash, anchor, "it extends the anchor");
    assert_eq!(
        rotation_answer(
            std::slice::from_ref(&ans),
            &history,
            gseq,
            &anchor,
            &txid,
            tier
        )
        .is_some(),
        e["answers"].as_bool().unwrap(),
        "a judge accepts it as the answer"
    );

    // The negative: C's operations re-signed with public test keys (C's own update cannot lose a
    // cosignature and keep its operator signature, which commits to them). Same heights, expiry,
    // rulesets, anchor and rungs; 3 member cosignatures answer, 2 do not.
    let syn = &v["synthetic"];
    let se = &syn["expect"];
    let shist = vec![
        update(syn, "ledger_open_hex"),
        update(syn, "governing_quorum_begin_hex"),
    ];
    let a3 = update(syn, "answer3_hex");
    let a2 = update(syn, "answer2_hex");
    assert!(a3.verify_operator_signature().is_ok() && a2.verify_operator_signature().is_ok());
    let (_, sneed) = answer_floor(&shist, gseq, tier).unwrap();
    assert_eq!(sneed as u64, se["tier_floor_needed"].as_u64().unwrap());
    let LedgerOperation::QuorumBegin {
        quorum_members: sm, ..
    } = LedgerOperation::tlv_decode(&shist[1].message).unwrap()
    else {
        panic!()
    };
    let smembers: Vec<_> = sm.iter().map(|m| m.pubkey.x_only_public_key().0).collect();
    assert_eq!(
        tier_cosignatures(&a3, &smembers) as u64,
        se["answer3_member_cosignatures"].as_u64().unwrap()
    );
    assert_eq!(
        tier_cosignatures(&a2, &smembers) as u64,
        se["answer2_member_cosignatures"].as_u64().unwrap()
    );
    assert_eq!(
        rotation_answer(
            std::slice::from_ref(&a3),
            &shist,
            gseq,
            &anchor,
            &txid,
            tier
        )
        .is_some(),
        se["answer3_answers"].as_bool().unwrap(),
        "with the ledger's recorded threshold it answers"
    );
    assert_eq!(
        rotation_answer(
            std::slice::from_ref(&a2),
            &shist,
            gseq,
            &anchor,
            &txid,
            tier
        )
        .is_some(),
        se["answer2_answers"].as_bool().unwrap(),
        "one cosignature below it, it answers nothing"
    );
    assert!(deposits_protocol::types::ruleset_recorded_threshold_answer(
        "strict-lottery-v8"
    ));
    assert!(!deposits_protocol::types::ruleset_recorded_threshold_answer("grounded-arms-v7"));
}

use bitcoin::hashes::Hash;
