//! DEP-05 §"Quorum expiry", against the vector shared with cl-deposits.

use deposits_protocol::types::{planned_quorum_expiry, quorum_expiry_ceiling, QuorumMember};

fn member(until: Option<u32>) -> QuorumMember {
    let pk = bitcoin::secp256k1::PublicKey::from_secret_key(
        &bitcoin::secp256k1::Secp256k1::new(),
        &bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
    );
    QuorumMember {
        pubkey: pk,
        ledger_id: String::new(),
        min_fee_bps: None,
        min_fee_fixed: None,
        max_fee_period: None,
        membership_until: until,
        dispute_response_blocks: None,
        dispute_arm_blocks: None,
        service_response_blocks: None,
        max_transfer_timeout_blocks: None,
        max_descriptor_bytes: None,
        compensation_bps: None,
        compensation_deposit_id: None,
        compensation_frequency_blocks: None,
        min_collateral_bps: None,
        dormancy_blocks: None,
        dormancy_notice_blocks: None,
        supported_rulesets: Vec::new(),
    }
}

#[test]
fn quorum_expiry_matches_the_shared_vector() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("vectors/quorum_expiry.json")).unwrap();
    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let members: Vec<QuorumMember> = case["commitments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| member(c.as_u64().map(|x| x as u32)))
            .collect();
        let ceiling = quorum_expiry_ceiling(members.iter());
        assert_eq!(ceiling.map(u64::from), case["ceiling"].as_u64(), "{}", name);
        let planned = planned_quorum_expiry(
            members.iter(),
            case["current_block"].as_u64().unwrap() as u32,
            case["window_blocks"].as_u64().unwrap() as u32,
        );
        assert_eq!(
            planned as u64,
            case["planned"].as_u64().unwrap(),
            "{}",
            name
        );
        for chk in case["checks"].as_array().unwrap() {
            let e = chk["expiry"].as_u64().unwrap() as u32;
            let ok = ceiling.map_or(true, |c| e <= c);
            assert_eq!(ok, chk["ok"].as_bool().unwrap(), "{}: expiry {}", name, e);
        }
    }
}
