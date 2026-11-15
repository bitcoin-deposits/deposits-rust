//! DEP-05 §"When a quorum_expired dispute ends", against the vector shared with cl-deposits.
//! A case with a `ruleset` is judged under it (strict-lottery-v8: a re-establishment ends the
//! dispute only once its spend of the vault confirmed); one without is read before v8.

use deposits_protocol::types::{
    arm_on_expiry_dispute, arm_on_expiry_dispute_under, expiry_dispute_ended,
    expiry_dispute_ended_under,
};

#[test]
fn expiry_dispute_ends_matches_the_shared_vector() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("vectors/expiry_dispute_ends.json")).unwrap();
    for c in v["ended"].as_array().unwrap() {
        let lvs = c["last_valid_sequence"].as_u64().unwrap();
        let qb = c["latest_quorum_begin_sequence"].as_u64().unwrap();
        let cc = c["confiscation_confirmed"].as_bool().unwrap();
        let got = match c["ruleset"].as_str() {
            Some(r) => expiry_dispute_ended_under(
                r,
                lvs,
                qb,
                cc,
                c["rotation_spend_confirmed"].as_bool().unwrap_or(true),
            ),
            None => expiry_dispute_ended(lvs, qb, cc),
        };
        assert_eq!(got, c["ended"].as_bool().unwrap(), "{}", c["name"]);
    }
    for c in v["arm"].as_array().unwrap() {
        let anchor = c["anchor_block_height"].as_u64().unwrap() as u32;
        let gov = c["governing_quorum_expiry"].as_u64().unwrap() as u32;
        let lvs = c["last_valid_sequence"].as_u64().unwrap();
        let qb = c["latest_quorum_begin_sequence"].as_u64().unwrap();
        let got = match c["ruleset"].as_str() {
            Some(r) => arm_on_expiry_dispute_under(
                r,
                anchor,
                gov,
                lvs,
                qb,
                c["rotation_spend_confirmed"].as_bool().unwrap_or(true),
            ),
            None => arm_on_expiry_dispute(anchor, gov, lvs, qb),
        };
        assert_eq!(got, c["arm"].as_bool().unwrap(), "{}", c["name"]);
    }
}
