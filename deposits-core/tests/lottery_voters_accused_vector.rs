//! strict-lottery-v8 (provisional): the lottery's recovery voters are the governing quorum
//! without the keys the dispute's own grounds convict, every threshold the strict majority of
//! what remains; none remaining leaves only the full-set leaf. Against the shared vector
//! `lottery_voters_accused.txt` that cl-deposits generates (inspect/gen-lottery-voters.lisp):
//! voters from secrets `[21..=25; 32]`, three participants from secrets `[1..=3; 32]` with
//! commitments `[i; 20]` and targets `tb1p<i>`, signet.

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::Network;
use deposits_core::tapscript_reserves::{LotteryParticipant, LotteryScriptBuilder};
use deposits_core::types::strict_voters;
use std::collections::HashMap;

fn xonly(seed: u8) -> bitcoin::secp256k1::XOnlyPublicKey {
    let secp = Secp256k1::new();
    PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap())
        .x_only_public_key()
        .0
}

fn list(v: &[String]) -> String {
    if v.is_empty() {
        "-".into()
    } else {
        v.join(",")
    }
}

#[test]
fn lottery_voters_accused_match_the_shared_vector() {
    let text = include_str!("vectors/lottery_voters_accused.txt");
    let mut cases = 0;
    for line in text.lines().filter(|l| l.starts_with("VEC ")) {
        let f: HashMap<&str, &str> = line[4..]
            .split(' ')
            .filter_map(|kv| kv.split_once('='))
            .collect();
        let accused: Vec<_> = if f["accused"] == "-" {
            vec![]
        } else {
            f["accused"]
                .split(',')
                .map(|s| xonly(s.parse().unwrap()))
                .collect()
        };
        let quorum: Vec<_> = (21..=25u8).map(xonly).collect();
        let (voters, threshold) = strict_voters(&quorum, &accused);
        let mut sorted = voters.clone();
        sorted.sort_by_key(|k| k.serialize());
        let name = f["case"];
        assert_eq!(
            list(
                &sorted
                    .iter()
                    .map(|k| hex::encode(k.serialize()))
                    .collect::<Vec<_>>()
            ),
            f["voters"],
            "{name} voters"
        );
        assert_eq!(threshold.to_string(), f["threshold"], "{name} threshold");
        let mut ps: Vec<LotteryParticipant> = (1..=3u8)
            .map(|i| LotteryParticipant::new(xonly(i), [i; 20], format!("tb1p{}", i)))
            .collect();
        ps.sort_by_key(|p| p.pubkey.serialize());
        let out = LotteryScriptBuilder::new(ps, voters, threshold, Network::Signet)
            .build()
            .unwrap();
        let tiers: Vec<String> = out
            .recovery_leaves()
            .iter()
            .map(|(_, t, _)| t.to_string())
            .collect();
        assert_eq!(list(&tiers), f["tiers"], "{name} tiers");
        let leaves = 1 + out.subset_scripts.len() + out.recovery_leaves().len();
        assert_eq!(leaves.to_string(), f["leaves"], "{name} leaf count");
        assert_eq!(out.address.to_string(), f["address"], "{name} address");
        let sub = out
            .subset_leaf(&[0, 1])
            .map(|s| hex::encode(s.as_bytes()))
            .unwrap_or_else(|| "-".into());
        assert_eq!(sub, f["subset01"], "{name} subset [0,1] leaf");
        let rec = out
            .recovery_leaves()
            .first()
            .map(|(_, _, s)| hex::encode(s.as_bytes()))
            .unwrap_or_else(|| "-".into());
        assert_eq!(rec, f["recovery144"], "{name} recovery leaf (CSV 144)");
        cases += 1;
    }
    assert_eq!(cases, 4, "every lottery_voters_accused case ran");
}
