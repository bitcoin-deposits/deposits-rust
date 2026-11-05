//! DEP-06 Phase 4 (draft): the re-arm round's recovery spend, against the
//! shared vector `rearm_spend.txt` that cl-deposits generates
//! (inspect/gen-rearm-spend.lisp). Keys follow `lottery_subsets.txt`:
//! participants from secrets `[i; 32]` with commitments `[i; 20]` and targets
//! `tb1p<i>`, voters from secrets `[20 + j; 32]` at threshold `r/2 + 1`,
//! signet. The spend is of `11..11:0` worth 50,000,000 sats into `5120 22..22`.

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Network, OutPoint, ScriptBuf, Txid};
use deposits_core::tapscript_reserves::{LotteryParticipant, LotteryScriptBuilder};
use std::collections::HashMap;

fn xonly(seed: u8) -> bitcoin::secp256k1::XOnlyPublicKey {
    let secp = Secp256k1::new();
    PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap())
        .x_only_public_key()
        .0
}

#[test]
fn rearm_spend_matches_the_shared_vector() {
    let text = include_str!("vectors/rearm_spend.txt");
    let mut next = vec![0x51u8, 0x20];
    next.extend_from_slice(&[0x22u8; 32]);
    let next = ScriptBuf::from_bytes(next);
    let outpoint = OutPoint {
        txid: Txid::from_byte_array([0x11; 32]),
        vout: 0,
    };
    let mut cases = 0;
    for line in text.lines().filter(|l| l.starts_with("VEC ")) {
        let f: HashMap<&str, &str> = line[4..]
            .split(' ')
            .filter_map(|kv| kv.split_once('='))
            .collect();
        let k: u8 = f["k"].parse().unwrap();
        let r: u8 = f["r"].parse().unwrap();
        let tier: usize = f["tier"].parse().unwrap();
        let feerate: u64 = f["feerate"].parse().unwrap();
        let mut participants: Vec<LotteryParticipant> = (1..=k)
            .map(|i| LotteryParticipant::new(xonly(i), [i; 20], format!("tb1p{}", i)))
            .collect();
        participants.sort_by_key(|a| a.pubkey.serialize());
        let voters: Vec<_> = (1..=r).map(|j| xonly(20 + j)).collect();
        let lottery =
            LotteryScriptBuilder::new(participants, voters, (r / 2 + 1) as usize, Network::Signet)
                .build()
                .unwrap();
        let (tx, fee, vsize) = lottery
            .rearm_spend(outpoint, 50_000_000, tier, next.clone(), feerate)
            .unwrap();
        let name = format!("k={} r={} tier={}", k, r, tier);
        assert_eq!(serialize_hex(&tx), f["tx"], "{} tx", name);
        assert_eq!(fee.to_string(), f["fee"], "{} fee", name);
        assert_eq!(vsize.to_string(), f["vsize"], "{} vsize", name);
        cases += 1;
    }
    assert_eq!(cases, 9, "every rearm_spend case ran");
}
