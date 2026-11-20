//! DEP-06 §Judging a proof, shared with cl-deposits (`inspect/vectors/proof_history_needs.json`)
//! and the spec (`vectors/proof_history_needs.json`): the history each evidence type rests on
//! ([`FraudProof::history_needs`]) and, for given replica tips, whether a member acts on the
//! proof, holds it until it has caught up, or refuses it ([`proof_verdict`]).

use deposits_protocol::fraud::{proof_verdict, FraudBroadcast, ProofVerdict};

#[test]
fn proof_history_needs_vector() {
    let doc: serde_json::Value =
        serde_json::from_str(include_str!("vectors/proof_history_needs.json")).unwrap();
    let mut n = 0;
    for case in doc["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let b: FraudBroadcast = serde_json::from_value(case["broadcast"].clone())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let want: Vec<(String, u64)> = case["needs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| (p[0].as_str().unwrap().to_string(), p[1].as_u64().unwrap()))
            .collect();
        assert_eq!(b.proof.history_needs(), want, "needs: {name}");
        for v in case["verdicts"].as_array().unwrap() {
            let tips = v["tips"].as_object().unwrap().clone();
            let tip_of = |l: &str| tips.get(l).and_then(|t| t.as_u64());
            let got = match proof_verdict(&want, tip_of, v["verifies"].as_bool().unwrap()) {
                ProofVerdict::Judge => "judge",
                ProofVerdict::Park => "park",
                ProofVerdict::Refuse => "refuse",
            };
            assert_eq!(got, v["expect"].as_str().unwrap(), "{name}: {v}");
            n += 1;
        }
    }
    assert_eq!(n, 62, "every verdict row was checked");
}
