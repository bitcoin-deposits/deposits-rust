//! DEP-06 "A yield binds only its author" (ruled 2026-11-24, latest counts):
//! `rotation_order::dispute_scope` against the scope cases of the shared vector
//! `deposits-protocol/tests/vectors/enter_after_yield.txt` (cl-deposits passes the same file;
//! its pledge cases run in deposits-node, `enter_after_yield_pledge_tests`).

use bitcoin::hashes::{sha256, Hash};
use deposits_core::messages::{LedgerOperation, QuorumMemberRef};
use deposits_core::rotation_order::dispute_scope;
use deposits_core::types::SignedLedgerUpdate;
use deposits_core::TlvEncode;

fn key(c: char) -> bitcoin::secp256k1::PublicKey {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&[c as u8; 32]).unwrap();
    bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
}

fn h(prefix: &str, s: &str) -> [u8; 32] {
    sha256::Hash::hash(format!("{}{}", prefix, s).as_bytes()).to_byte_array()
}
fn tag_hash(tag: &str) -> [u8; 32] {
    h("enter_after_yield:", tag)
}
fn txid(name: &str) -> [u8; 32] {
    h("tx:", name)
}
/// An update's chain hash, SHA256(content_hash || operator_signature), the signature 64 x 0.
fn chain_of(tag: &str) -> [u8; 32] {
    let mut b = tag_hash(tag).to_vec();
    b.extend_from_slice(&[0u8; 64]);
    sha256::Hash::hash(&b).to_byte_array()
}

fn opt<'a>(w: &'a [&'a str], k: &str) -> Option<&'a str> {
    w.iter().find_map(|t| t.strip_prefix(k))
}

fn op_of(w: &[&str], refh: &dyn Fn(&str) -> [u8; 32]) -> LedgerOperation {
    match w[0] {
        "open" => LedgerOperation::LedgerOpen {
            operator_id: key('o'),
            reserves_id: "r".into(),
            genesis_block: 0,
            reserves_amount: 1,
            collateral_amount: 1,
            protocol_version: None,
        },
        "qb" => LedgerOperation::QuorumBegin {
            exit_cutoff_height: None,
            exit_outputs: Vec::new(),
            splice_in_outpoint: None,
            splice_in_amount: None,
            reference_feerate: None,
            dormancy_outputs: Vec::new(),
            migration_manifest: Vec::new(),
            migration_receiver: None,
            migration_vout: None,
            consumed_notice: None,
            rotation_rungs: vec![],
            reserves_id: "r".into(),
            spending_txid: [0; 32],
            new_outpoint_txid: opt(w, "tx=").map(txid).unwrap_or([1; 32]),
            new_outpoint_vout: 0,
            amount: 1,
            quorum_expiry: 1_000_000,
            ledger_hash: [0; 32],
            quorum_members: vec![QuorumMemberRef::pubkey_only(key('m'))],
            collateral_amount: 1,
            protocol_version: Some("cltv-offset-v2".into()),
        },
        "enter" => LedgerOperation::DisputeEnter {
            last_valid_sequence: w[1].parse().unwrap(),
            reason: if w.contains(&"punitive") {
                "equivocation".into()
            } else {
                "quorum_expired".into()
            },
            anchor_block_hash: None,
            anchor_block_height: None,
            fraud_proof_hash: None,
            fraud_proof: None,
        },
        "arm" => LedgerOperation::DisputeArmed {
            armed_block: 0,
            commitment_hash: [0; 20],
            target_reserves: String::new(),
            replacement_collateral: None,
            rearm_round: w
                .get(1)
                .and_then(|r| r.parse().ok())
                .filter(|r: &u32| *r > 1),
        },
        "acquire" => LedgerOperation::DisputeAcquire {
            new_custodian: key('m'),
            claim_txid: txid("claim"),
            new_reserves_address: String::new(),
            confiscation_txid: None,
        },
        "yield" => LedgerOperation::DisputeYield {
            lost_to: opt(w, "lost_to=").map(txid),
            reestablished: opt(w, "reestablished=").map(refh),
            excluded_by: opt(w, "excluded_by=").map(txid),
            superseded_by: opt(w, "superseded_by=").map(refh),
        },
        _ => LedgerOperation::dispute_yield(),
    }
}

#[test]
fn enter_after_yield_vector() {
    let text = include_str!("../../deposits-protocol/tests/vectors/enter_after_yield.txt");
    let mut name = String::new();
    let mut ups: Vec<SignedLedgerUpdate> = Vec::new();
    let mut tags: Vec<String> = Vec::new();
    let mut fork_of: Vec<String> = Vec::new(); // the enter tag each disputant update is on
    let mut cases = 0;
    let mut orderings = 0;
    let mut in_case = false;
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let w: Vec<&str> = line.split_whitespace().collect();
        match w[0] {
            "case" => {
                in_case = true;
                name = w[1].to_string();
                ups.clear();
                tags.clear();
                fork_of.clear();
            }
            "pledge" => in_case = false,
            _ if !in_case => {}
            "u" => {
                let who = w[1].chars().next().unwrap();
                let seq: u64 = w[2].parse().unwrap();
                let rest = &w[3..];
                let tag = opt(rest, "as=")
                    .map(String::from)
                    .unwrap_or(format!("{}:{}", who, seq));
                let built = |t: &str| tags.iter().position(|x| x == t).map(|i| &ups[i]);
                let refh = |t: &str| built(t).map(|u| u.content_hash).unwrap_or_else(|| tag_hash(t));
                let chain_of = |t: &str| built(t).map(|u| u.chain_hash()).unwrap_or_else(|| chain_of(t));
                let op = op_of(rest, &refh);
                let previous_hash = if who == 'o' {
                    (0..ups.len())
                        .rev()
                        .find(|&i| ups[i].operator_id == key('o'))
                        .map(|i| ups[i].chain_hash())
                        .unwrap_or([0; 32])
                } else if rest[0] == "enter" && !rest.contains(&"cont") {
                    if rest.contains(&"offledger") {
                        [0xEE; 32]
                    } else {
                        chain_of(&format!("o:{}", rest[1]))
                    }
                } else {
                    let fork = opt(rest, "on=").map(String::from).unwrap_or_else(|| {
                        (0..ups.len())
                            .rev()
                            .find(|&i| ups[i].operator_id == key(who) && fork_of[i] == tags[i])
                            .map(|i| tags[i].clone())
                            .expect("a disputant update needs a DisputeEnter before it")
                    });
                    let last = (0..ups.len())
                        .rev()
                        .find(|&i| ups[i].operator_id == key(who) && fork_of[i] == fork)
                        .map(|i| tags[i].clone())
                        .unwrap_or(fork.clone());
                    chain_of(&last)
                };
                let fork = if who == 'o' {
                    String::new()
                } else if rest[0] == "enter" {
                    tag.clone()
                } else {
                    tag_hash_fork(&ups, &tags, &fork_of, &previous_hash)
                };
                let mut u = SignedLedgerUpdate {
                    message: op.tlv_encode(),
                    message_type: 1,
                    operator_id: key(who),
                    ledger_id: [9; 32],
                    sequence_number: seq,
                    previous_hash,
                    content_hash: [0; 32],
                    block_height: opt(rest, "h=").map(|x| x.parse().unwrap()).unwrap_or(0),
                    block_hash: [1; 32],
                    operator_signature: [0; 64],
                    cosignatures: Vec::new(),
                };
                u.content_hash = u.compute_hash();
                ups.push(u);
                tags.push(tag);
                fork_of.push(fork);
            }
            "expect" => {
                let kept = dispute_scope(&ups);
                let got: Vec<String> = kept
                    .iter()
                    .map(|k| tags[ups.iter().position(|u| u == k).unwrap()].clone())
                    .collect();
                let want: Vec<String> = w[1..].iter().map(|s| s.to_string()).collect();
                assert_eq!(got, want, "case {}", name);
                cases += 1;
                // a function of the SET: every order of the same updates, the same scope
                let mut sorted_want = want.clone();
                sorted_want.sort();
                let orders = permutations_or_shuffles(ups.len());
                for ord in &orders {
                    let perm: Vec<SignedLedgerUpdate> = ord.iter().map(|&i| ups[i].clone()).collect();
                    let mut got: Vec<String> = dispute_scope(&perm)
                        .iter()
                        .map(|k| tags[ups.iter().position(|u| u == k).unwrap()].clone())
                        .collect();
                    got.sort();
                    assert_eq!(got, sorted_want, "case {} in order {:?}", name, ord);
                }
                orderings += orders.len();
            }
            "end" => {}
            _ => panic!("case {}: {}", name, line),
        }
    }
    assert_eq!(cases, 19);
    assert!(orderings > 1000, "{} orders", orderings);
}

/// The fork (its DisputeEnter's tag) of the update whose content hash is `prev`.
fn tag_hash_fork(
    ups: &[SignedLedgerUpdate],
    tags: &[String],
    fork_of: &[String],
    prev: &[u8; 32],
) -> String {
    let i = ups.iter().position(|u| u.chain_hash() == *prev).unwrap();
    fork_of[i].clone()
}

/// Every permutation of 0..n when n <= 6, else the identity, its reverse and 300 fixed shuffles
/// (a 31-bit LCG seeded at 1), as cl-deposits' PERMUTATIONS-OR-SHUFFLES.
fn permutations_or_shuffles(n: usize) -> Vec<Vec<usize>> {
    fn perms(l: &[usize]) -> Vec<Vec<usize>> {
        if l.is_empty() {
            return vec![vec![]];
        }
        let mut out = Vec::new();
        for (k, &x) in l.iter().enumerate() {
            let mut rest = l.to_vec();
            rest.remove(k);
            for mut p in perms(&rest) {
                p.insert(0, x);
                out.push(p);
            }
        }
        out
    }
    let ids: Vec<usize> = (0..n).collect();
    if n <= 6 {
        return perms(&ids);
    }
    let mut out = vec![ids.clone(), ids.iter().rev().copied().collect()];
    let mut seed: u64 = 1;
    for _ in 0..300 {
        let mut v = ids.clone();
        for i in (1..n).rev() {
            seed = (seed * 1_103_515_245 + 12_345) % 2_147_483_648;
            v.swap(i, (seed % (i as u64 + 1)) as usize);
        }
        out.push(v);
    }
    out
}
