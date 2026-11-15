//! DEP-06 Phase 4: a re-arm spend's witness stack as the proposer assembles it, against the
//! shared vector `rearm_witness.txt` that cl-deposits generates (inspect/gen-rearm-witness.lisp).
//! Lotteries as `rearm_spend.txt`; `mask` names, in the sorted recovery-voter order, which voters
//! signed, and voter `i`'s signature is 64 bytes of `0x40 + i`.

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::Network;
use deposits_core::tapscript_reserves::{LotteryParticipant, LotteryScriptBuilder};
use std::collections::HashMap;

fn xonly(seed: u8) -> bitcoin::secp256k1::XOnlyPublicKey {
    let secp = Secp256k1::new();
    PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap())
        .x_only_public_key()
        .0
}

#[test]
fn rearm_witness_matches_the_shared_vector() {
    let text = include_str!("vectors/rearm_witness.txt");
    let mut cases = 0;
    for line in text.lines().filter(|l| l.starts_with("VEC ")) {
        let f: HashMap<&str, &str> = line[4..]
            .split(' ')
            .filter_map(|kv| kv.split_once('='))
            .collect();
        let k: u8 = f["k"].parse().unwrap();
        let r: u8 = f["r"].parse().unwrap();
        let tier: usize = f["tier"].parse().unwrap();
        let mut participants: Vec<LotteryParticipant> = (1..=k)
            .map(|i| LotteryParticipant::new(xonly(i), [i; 20], format!("tb1p{}", i)))
            .collect();
        participants.sort_by_key(|a| a.pubkey.serialize());
        let voters: Vec<_> = (1..=r).map(|j| xonly(20 + j)).collect();
        let lottery =
            LotteryScriptBuilder::new(participants, voters, (r / 2 + 1) as usize, Network::Signet)
                .build()
                .unwrap();
        let sigs: Vec<Option<[u8; 64]>> = f["mask"]
            .chars()
            .enumerate()
            .map(|(i, c)| (c == '1').then_some([0x40 + i as u8; 64]))
            .collect();
        let w = lottery.recovery_witness(tier, &sigs).unwrap();
        let got: Vec<String> = w.iter().map(hex::encode).collect();
        assert_eq!(
            got.join(","),
            f["witness"],
            "k={} r={} tier={} mask={}",
            k,
            r,
            tier,
            f["mask"]
        );
        cases += 1;
    }
    assert_eq!(cases, 8, "every rearm_witness case ran");
}
