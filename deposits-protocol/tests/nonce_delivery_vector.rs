//! DEP-17 §nonce and expiry and §duplicate delivery, against the vector shared with
//! cl-deposits (inspect/vectors/nonce_delivery.json).

use deposits_protocol::types::nonce_verdict;

fn hash(v: &serde_json::Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn nonce_delivery_matches_the_shared_vector() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("vectors/nonce_delivery.json")).unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 10);
    for case in cases {
        let accepted: Vec<(u64, u32, [u8; 32])> = case["accepted"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                (
                    a["nonce"].as_u64().unwrap(),
                    a["expiry"].as_u64().unwrap() as u32,
                    hash(&a["sighash"]),
                )
            })
            .collect();
        let op = &case["op"];
        let got = nonce_verdict(
            &accepted,
            op["nonce"].as_u64().unwrap(),
            op["expiry"].as_u64().unwrap() as u32,
            &hash(&op["sighash"]),
            case["height"].as_u64().unwrap() as u32,
        );
        assert_eq!(
            got.as_str(),
            case["verdict"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }
}
