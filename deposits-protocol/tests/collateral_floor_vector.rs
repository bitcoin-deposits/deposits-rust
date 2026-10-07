//! DEP-05 §"Collateral floor", against the vector shared with cl-deposits.

use deposits_protocol::types::{collateral_floor_bps, collateral_meets_floor, QuorumMember};

#[test]
fn collateral_floor_matches_the_shared_vector() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("vectors/collateral_floor.json")).unwrap();
    let pk = bitcoin::secp256k1::PublicKey::from_secret_key(
        &bitcoin::secp256k1::Secp256k1::new(),
        &bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
    );
    for case in v["cases"].as_array().unwrap() {
        let members: Vec<QuorumMember> = case["member_bps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| QuorumMember {
                pubkey: pk,
                ledger_id: String::new(),
                min_fee_bps: None,
                min_fee_fixed: None,
                max_fee_period: None,
                membership_until: None,
                dispute_response_blocks: None,
                dispute_arm_blocks: None,
                service_response_blocks: None,
                max_transfer_timeout_blocks: None,
                max_descriptor_bytes: None,
                compensation_bps: None,
                compensation_deposit_id: None,
                compensation_frequency_blocks: None,
                min_collateral_bps: b.as_u64().map(|x| x as u16),
                dormancy_blocks: None,
                dormancy_notice_blocks: None,
                supported_rulesets: Vec::new(),
            })
            .collect();
        let floor = collateral_floor_bps(members.iter());
        let name = case["name"].as_str().unwrap();
        assert_eq!(
            floor as u64,
            case["floor_bps"].as_u64().unwrap(),
            "{}",
            name
        );
        let ok = collateral_meets_floor(
            case["reserves"].as_u64().unwrap(),
            case["collateral"].as_u64().unwrap(),
            floor,
        );
        assert_eq!(ok, case["ok"].as_bool().unwrap(), "{}", name);
    }
}
