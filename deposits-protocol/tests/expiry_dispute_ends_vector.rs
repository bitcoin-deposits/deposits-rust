//! DEP-05 §"When a quorum_expired dispute ends", against the vector shared with cl-deposits.

use deposits_protocol::types::{arm_on_expiry_dispute, expiry_dispute_ended};

#[test]
fn expiry_dispute_ends_matches_the_shared_vector() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("vectors/expiry_dispute_ends.json")).unwrap();
    for c in v["ended"].as_array().unwrap() {
        assert_eq!(
            expiry_dispute_ended(
                c["last_valid_sequence"].as_u64().unwrap(),
                c["latest_quorum_begin_sequence"].as_u64().unwrap(),
                c["confiscation_confirmed"].as_bool().unwrap(),
            ),
            c["ended"].as_bool().unwrap(),
            "{}",
            c["name"]
        );
    }
    for c in v["arm"].as_array().unwrap() {
        assert_eq!(
            arm_on_expiry_dispute(
                c["anchor_block_height"].as_u64().unwrap() as u32,
                c["governing_quorum_expiry"].as_u64().unwrap() as u32,
                c["last_valid_sequence"].as_u64().unwrap(),
                c["latest_quorum_begin_sequence"].as_u64().unwrap(),
            ),
            c["arm"].as_bool().unwrap(),
            "{}",
            c["name"]
        );
    }
}
