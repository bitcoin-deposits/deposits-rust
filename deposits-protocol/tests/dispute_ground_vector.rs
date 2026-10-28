//! DEP-05 §"The ground of a dispute", against the vector shared with cl-deposits.

use deposits_protocol::types::dispute_is_expiry;

#[test]
fn dispute_ground_matches_the_shared_vector() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("vectors/dispute_ground.json")).unwrap();
    for c in v["cases"].as_array().unwrap() {
        assert_eq!(
            dispute_is_expiry(
                c["reason"].as_str().unwrap(),
                c["has_anchor"].as_bool().unwrap(),
                c["cites_proof"].as_bool().unwrap(),
                c["enter_block_height"].as_u64().unwrap() as u32,
                c["governing_quorum_expiry"].as_u64().map(|e| e as u32),
            ),
            c["expiry"].as_bool().unwrap(),
            "{}",
            c["name"]
        );
    }
}
