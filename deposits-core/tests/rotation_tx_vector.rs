//! DEP-03 §"Rotation transaction" and §Fee ladder: every rung of the unsigned rotation, byte
//! for byte, pinned by the vector shared with cl-deposits (inspect/vectors/rotation_tx.txt
//! there, which writes the rung lines). Each case carries its own inputs (the vault, voters,
//! feerate, locktime, new vault, extras, splice, anchor, the collateral bounding the ladder, at
//! most how many rungs), so this implementation rebuilds from the file alone.

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{OutPoint, ScriptBuf, Txid};
use deposits_core::tapscript_reserves::{
    anchor_of, build_rotation_ladder, build_rotation_tx, rotation_vsize, RotationTxParams,
    ROTATION_RUNGS,
};
use std::str::FromStr;

struct Case {
    name: String,
    p: RotationTxParams,
    collateral: u64,
    max_rungs: usize,
    rungs: Vec<String>,
}

fn cases() -> Vec<Case> {
    let text = include_str!("vectors/rotation_tx.txt");
    let mut out: Vec<Case> = Vec::new();
    let outpoint = |s: &str| {
        let (t, v) = s.split_once(':').unwrap();
        OutPoint::new(Txid::from_str(t).unwrap(), v.parse().unwrap())
    };
    for line in text.lines().filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let w: Vec<&str> = line.split(' ').collect();
        if w[0] == "case" {
            out.push(Case {
                name: w[1].to_string(),
                p: RotationTxParams {
                    vault: OutPoint::null(),
                    vault_sats: 0,
                    voters: 0,
                    feerate_sat_vb: 0,
                    lock_time: 0,
                    new_vault_spk: ScriptBuf::new(),
                    splice_in: None,
                    splice_vault: false,
                    extra_outputs: vec![],
                    anchor: [0; 32],
                    rung: 0,
                },
                collateral: 0,
                max_rungs: ROTATION_RUNGS,
                rungs: vec![],
            });
            continue;
        }
        let c = out.last_mut().unwrap();
        match w[0] {
            "vault" => {
                c.p.vault = outpoint(w[1]);
                c.p.vault_sats = w[2].parse().unwrap();
            }
            "voters" => c.p.voters = w[1].parse().unwrap(),
            "feerate" => c.p.feerate_sat_vb = w[1].parse().unwrap(),
            "locktime" => c.p.lock_time = w[1].parse().unwrap(),
            "new_vault_spk" => c.p.new_vault_spk = ScriptBuf::from_hex(w[1]).unwrap(),
            "splice" => c.p.splice_in = Some((outpoint(w[1]), w[2].parse().unwrap())),
            "splice_vault" => c.p.splice_vault = w[1] == "1",
            "out" => c
                .p
                .extra_outputs
                .push((ScriptBuf::from_hex(w[1]).unwrap(), w[2].parse().unwrap())),
            "anchor" => c.p.anchor = hex::decode(w[1]).unwrap().try_into().unwrap(),
            "collateral" => c.collateral = w[1].parse().unwrap(),
            "max_rungs" => c.max_rungs = w[1].parse().unwrap(),
            "rung" => c.rungs.push(w[2].to_string()),
            k => panic!("unknown key {k}"),
        }
    }
    out
}

#[test]
fn rotation_ladder_matches_shared_vector() {
    let cases = cases();
    assert_eq!(cases.len(), 5, "five shapes");
    for c in &cases {
        let ours: Vec<String> = build_rotation_ladder(&c.p, c.collateral, c.max_rungs)
            .unwrap()
            .iter()
            .map(serialize_hex)
            .collect();
        assert_eq!(ours, c.rungs, "{}", c.name);
    }
}

#[test]
fn rungs_follow_the_ladder_rules() {
    let c = &cases()[0];
    let rungs = build_rotation_ladder(&c.p, c.collateral, c.max_rungs).unwrap();
    let fee = |t: &bitcoin::Transaction| {
        c.p.vault_sats - t.output.iter().map(|o| o.value.to_sat()).sum::<u64>()
    };
    assert!(rungs.iter().all(|t| anchor_of(t) == Some(c.p.anchor)));
    for w in rungs.windows(2) {
        assert_eq!(fee(&w[1]), 2 * fee(&w[0]), "each rung doubles the fee (BIP-125)");
        assert_eq!(w[0].input, w[1].input);
        assert_eq!(
            w[0].output[1..].to_vec(),
            w[1].output[1..].to_vec(),
            "rungs differ only in the new vault"
        );
    }
    assert_eq!(rotation_vsize(8, &[34, 34], false, false) - rotation_vsize(8, &[34], false, false), 43);
}

#[test]
fn rotation_below_dust_is_refused() {
    let mut p = cases().remove(0).p;
    p.vault_sats = 900;
    assert!(build_rotation_tx(&p).is_none());
}
