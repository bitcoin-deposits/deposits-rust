//! DEP-06 §Entering a dispute, shared with cl-deposits (`tests/vectors/dispute_entry.txt`):
//! which proof types need an embedding, and whether the rule lets a member enter a dispute
//! on a proof whose own evidence verified, given how its broadcast carries the embedding.
//! The rule holds under every ruleset, so each case is stated under v6 and v7 alike.

use deposits_protocol::fraud::FraudProofType;

#[test]
fn dispute_entry_vector() {
    let text = include_str!("vectors/dispute_entry.txt");
    let mut n = 0;
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') || line.starts_with("forkpoint ") {
            continue;
        }
        let w: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(w.len(), 6, "{line}");
        assert_eq!(w[0], "case", "{line}");
        let t: FraudProofType = serde_json::from_str(&format!("\"{}\"", w[1]))
            .unwrap_or_else(|e| panic!("{line}: {e}"));
        let embedding_verified = match w[2] {
            "none" | "placeholder" => false,
            "valid" => true,
            other => panic!("{line}: embedding {other}"),
        };
        assert_eq!(t.requires_embedding(), w[4] == "1", "{line}");
        let entry = if t.entry_permitted(embedding_verified) {
            "permitted"
        } else {
            "refused"
        };
        assert_eq!(entry, w[5], "{line}");
        n += 1;
    }
    assert_eq!(n, 66, "eleven types, three embeddings, two rulesets");
}
