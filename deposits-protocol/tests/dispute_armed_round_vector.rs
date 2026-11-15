//! DisputeArmed's `rearm_round` (TLV 366, DEP-06 Phase 4) against the vector shared with
//! cl-deposits (`inspect/vectors/dispute_armed_round.json`): both encodings byte for byte, and
//! the round decoded back.
use deposits_protocol::{LedgerOperation, ReplacementCollateral, TlvDecode, TlvEncode};

#[test]
fn dispute_armed_round_matches_the_shared_vector() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("vectors/dispute_armed_round.json")).unwrap();
    for case in v["cases"].as_array().unwrap() {
        let round = case["rearm_round"].as_u64().map(|r| r as u32);
        let op = LedgerOperation::DisputeArmed {
            armed_block: 100,
            commitment_hash: [0x11; 20],
            target_reserves: "bcrt1qtarget".into(),
            replacement_collateral: Some(ReplacementCollateral {
                txid: [3; 32],
                vout: 1,
                amount: 50_000,
            }),
            rearm_round: round,
        };
        let want = hex::decode(case["hex"].as_str().unwrap()).unwrap();
        assert_eq!(op.tlv_encode(), want, "{}: encoding", case["name"]);
        match LedgerOperation::tlv_decode(&want).unwrap() {
            LedgerOperation::DisputeArmed { rearm_round, .. } => {
                assert_eq!(rearm_round, round, "{}: decoded round", case["name"])
            }
            other => panic!("{}: decoded {:?}", case["name"], other),
        }
    }
}
