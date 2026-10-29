//! DEP-18 ruleset gating, against the vector cl-deposits generates
//! (tests/vectors/ruleset_gating.txt): the registry, and each rule `anchor-ladder-v5` gates judged
//! on the same input under it (where it convicts), under an earlier ruleset, and under none
//! (dormant). The vault-spend twins are in vault_spend_anchor.txt.
use deposits_core::dep16::Dep16Authorizer;
use deposits_core::fraud::{
    verify_non_conforming_update, FraudEvidence, FraudProof, FraudProofType,
};
use deposits_core::types::SignedLedgerUpdate;
use deposits_core::{TlvDecode, TlvEncode};
use deposits_protocol::types::{
    collateral_meets_floor, quorum_born_expired, reserves_family, ruleset_forbids_born_expired,
    ruleset_proves_vault_spends, ruleset_requires_balance_commitments,
    ruleset_requires_collateral_floor, ruleset_requires_signed_header,
};

fn rs(w: &str) -> &str {
    if w == "-" {
        ""
    } else {
        w
    }
}

#[test]
fn ruleset_gating_matches_cl() {
    let dec = |h: &str| SignedLedgerUpdate::tlv_decode(&hex::decode(h).unwrap()).unwrap();
    let mut name = String::new();
    let mut history: Vec<SignedLedgerUpdate> = Vec::new();
    let mut fault: Option<SignedLedgerUpdate> = None;
    let mut counts = [0usize; 4];
    for line in include_str!("vectors/ruleset_gating.txt").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let w: Vec<&str> = line.split(' ').collect();
        match w[0] {
            "ruleset" => {
                counts[0] += 1;
                let name = w[1];
                assert!(
                    deposits_core::ruleset::lookup(name).is_some(),
                    "{name} is registered"
                );
                assert_eq!(reserves_family(name), w[3], "{name}: family");
                let mut want: Vec<&str> = if w[5] == "-" {
                    vec![]
                } else {
                    w[5].split(',').collect()
                };
                want.sort();
                let mut got = vec![];
                for (rule, on) in [
                    ("signed_header", ruleset_requires_signed_header(name)),
                    ("born_expired", ruleset_forbids_born_expired(name)),
                    ("collateral_floor", ruleset_requires_collateral_floor(name)),
                    ("vault_spend_proofs", ruleset_proves_vault_spends(name)),
                    (
                        "missing_balance_commitment",
                        ruleset_requires_balance_commitments(name),
                    ),
                ] {
                    if on {
                        got.push(rule);
                    }
                }
                got.sort();
                assert_eq!(got, want, "{name}: its gated rules");
            }
            "born_expired" => {
                counts[1] += 1;
                let (e, h): (u32, u32) = (w[2].parse().unwrap(), w[3].parse().unwrap());
                let v = ruleset_forbids_born_expired(rs(w[1])) && quorum_born_expired(e, h);
                assert_eq!(if v { "1" } else { "0" }, w[4], "born expired: {line}");
            }
            "collateral_floor" => {
                counts[2] += 1;
                let (r, c, f): (u64, u64, u16) = (
                    w[2].parse().unwrap(),
                    w[3].parse().unwrap(),
                    w[4].parse().unwrap(),
                );
                let v =
                    ruleset_requires_collateral_floor(rs(w[1])) && !collateral_meets_floor(r, c, f);
                assert_eq!(if v { "1" } else { "0" }, w[5], "collateral floor: {line}");
            }
            "case" => {
                name = w[1].to_string();
                history.clear();
            }
            "update" => history.push(dec(w[1])),
            "fault" => fault = Some(dec(w[1])),
            "verdict" => {
                counts[3] += 1;
                let f = fault.take().unwrap();
                let proof = FraudProof {
                    proof_type: FraudProofType::NonConformingUpdate,
                    accused: hex::encode(f.operator_id.serialize()),
                    ledger_id: hex::encode(f.ledger_id),
                    evidence: FraudEvidence::NonConformingUpdate {
                        fault_sequence: f.sequence_number,
                        fault_update_hex: hex::encode(f.tlv_encode()),
                    },
                };
                let got = verify_non_conforming_update(&proof, &history, &Dep16Authorizer::new());
                assert_eq!(
                    if got.is_ok() { "1" } else { "0" },
                    w[1],
                    "case {name}: {got:?}"
                );
            }
            other => panic!("unknown line {other}"),
        }
    }
    assert_eq!(counts, [4, 12, 8, 12]);
}
