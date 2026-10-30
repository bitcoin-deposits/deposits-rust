//! DEP-16 §Descriptor validity, pinned by the shared vector
//! `deposits-protocol/tests/vectors/descriptor_validity.json` (cl-deposits
//! passes the same file).

use deposits_core::dep16::validity::descriptor_violation;

#[test]
fn descriptor_validity_vector() {
    let text = include_str!("../../deposits-protocol/tests/vectors/descriptor_validity.json");
    let v: serde_json::Value = serde_json::from_str(text).unwrap();
    let mut wrong = Vec::new();
    let cases = v["cases"].as_array().unwrap();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let bytes = hex::decode(c["descriptor_hex"].as_str().unwrap()).unwrap();
        let d = String::from_utf8(bytes).unwrap();
        let mut verdict = descriptor_violation(&d);
        if verdict.is_none() {
            if let Some(max) = c.get("max_descriptor_bytes").and_then(|m| m.as_u64()) {
                if d.len() as u64 > max {
                    verdict = Some(format!("{} bytes over the cap {}", d.len(), max));
                }
            }
        }
        let expected = c["valid"].as_bool().unwrap();
        if verdict.is_none() != expected {
            wrong.push(format!(
                "{}: expected valid={} got {:?}",
                name, expected, verdict
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} cases disagree:\n{}",
        wrong.len(),
        cases.len(),
        wrong.join("\n")
    );
}
