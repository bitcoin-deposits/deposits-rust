//! DEP-05 §Cosignature Threshold and DEP-06 §Race, a rotation past expiry, against the vector
//! shared with cl-deposits (inspect/vectors/post_expiry_rotation.json).

use deposits_protocol::types::{
    expiry_dispute_outcome, member_cosigns_post_expiry, rung_sign_policy_allows,
};

#[test]
fn post_expiry_rotation_matches_the_shared_vector() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("vectors/post_expiry_rotation.json")).unwrap();
    for c in v["cosign"].as_array().unwrap() {
        assert_eq!(
            member_cosigns_post_expiry(
                c["block_height"].as_u64().unwrap() as u32,
                c["quorum_expiry"].as_u64().map(|e| e as u32),
                c["establishment"].as_bool().unwrap(),
                c["cosign_post_expiry"].as_bool().unwrap(),
            ),
            c["cosign"].as_bool().unwrap(),
            "{}",
            c["name"]
        );
    }
    for c in v["outcome"].as_array().unwrap() {
        let (y, r) = expiry_dispute_outcome(
            c["armed"].as_bool().unwrap(),
            c["reestablished"].as_bool().unwrap(),
            c["confiscation_confirmed"].as_bool().unwrap(),
        );
        assert_eq!(y, c["yield"].as_bool().unwrap(), "{}: yield", c["name"]);
        assert_eq!(r, c["release_pledge"].as_bool().unwrap(), "{}: pledge", c["name"]);
    }
    for c in v["rung_sign"].as_array().unwrap() {
        assert_eq!(
            rung_sign_policy_allows(
                c["qb_block_height"].as_u64().unwrap() as u32,
                c["old_quorum_expiry"].as_u64().map(|e| e as u32),
                c["cosign_post_expiry"].as_bool().unwrap(),
            ),
            c["sign"].as_bool().unwrap(),
            "{}",
            c["name"]
        );
    }
}
