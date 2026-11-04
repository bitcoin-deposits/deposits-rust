//! DEP-03 §Lottery, shared with cl-deposits (`tests/vectors/lottery_accused.txt`): a key the
//! dispute's own grounds convict never wins its lottery. `accused` cases check
//! [`FraudProof::accused_keys`] against the keys cl's `proof-accused-keys` derives from the same
//! proof; `cut` cases check the cut drops exactly the accused armers, keeping order (the
//! deposits-node eligibility cut applies the same filter before the snapshot).

use deposits_protocol::fraud::FraudBroadcast;

fn keys(s: &str) -> Vec<String> {
    if s == "none" {
        vec![]
    } else {
        s.split_whitespace().map(str::to_string).collect()
    }
}

#[test]
fn lottery_accused_vector() {
    let text = include_str!("vectors/lottery_accused.txt");
    let mut kind = String::new();
    let mut name = String::new();
    let mut fields: std::collections::HashMap<String, String> = Default::default();
    let mut n = 0;
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (head, rest) = line.split_once(' ').unwrap_or((line, ""));
        match head {
            "accused" if kind == "cut" => {
                fields.insert("accused".into(), rest.into());
            }
            "accused" | "cut" => {
                kind = head.into();
                name = rest.into();
                fields.clear();
            }
            "end" => {
                n += 1;
                let expect = fields.get("expect").cloned().unwrap_or_default();
                let got = if kind == "accused" {
                    let b: FraudBroadcast = serde_json::from_str(&fields["proof"])
                        .unwrap_or_else(|e| panic!("{name}: {e}"));
                    let mut k: Vec<String> = b
                        .proof
                        .accused_keys()
                        .iter()
                        .map(|k| hex::encode(k.serialize()))
                        .collect();
                    k.sort();
                    k
                } else {
                    let accused = keys(&fields["accused"]);
                    keys(&fields["armers"])
                        .into_iter()
                        .filter(|a| !accused.contains(a))
                        .collect()
                };
                let got = if got.is_empty() {
                    "none".to_string()
                } else {
                    got.join(" ")
                };
                assert_eq!(got, expect, "{kind} {name}");
                kind.clear();
            }
            _ => {
                fields.insert(head.into(), rest.into());
            }
        }
    }
    assert_eq!(n, 14, "every lottery_accused case ran");
}
