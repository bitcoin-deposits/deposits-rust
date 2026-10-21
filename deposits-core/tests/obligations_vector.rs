//! DEP-06 §Confiscation obligations, against the vectors cl-deposits generates: owed entries
//! (splice-out or residue), the pinned confiscation shape with sweeps and splice-outs, the
//! ObligationRecord fold, the residue-only MigrationCredit after a custody change, and proof 11.
use bitcoin::consensus::encode::serialize_hex;
use deposits_core::fraud::{
    unhonoured_obligation_proof, verify_unhonoured_obligation, FraudEvidence, FraudProof,
    FraudProofType,
};
use deposits_core::messages::{LedgerOperation, ManifestEntry};
use deposits_core::tapscript_reserves::{build_confiscation_tx, ConfiscationTxParams};
use deposits_core::types::{
    owed_spk_sats, with_apply_ctx, ApplyCtx, DisputeState, FeeStructure, LedgerState,
    SignedLedgerUpdate,
};
use deposits_core::{TlvDecode, TlvEncode};
use std::collections::HashMap;

fn at(h: u32) -> ApplyCtx {
    ApplyCtx {
        height: h,
        seq: 1,
        hash: [0; 32],
    }
}
fn txid(hex_display: &str) -> bitcoin::OutPoint {
    let b: [u8; 32] = hex::decode(hex_display).unwrap().try_into().unwrap();
    use bitcoin::hashes::Hash;
    bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array(b), 0)
}

#[test]
fn confiscation_obligations_match_cl() {
    let mut kv: HashMap<String, String> = HashMap::new();
    let mut residue_state: Option<LedgerState> = None;
    let mut n = 0;
    for line in include_str!("vectors/confiscation_obligations.txt").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let w: Vec<&str> = line.split(' ').collect();
        let field = |k: &str| {
            w.iter()
                .find_map(|s| s.strip_prefix(k))
                .unwrap_or_default()
                .to_string()
        };
        match w[0] {
            "case" => {}
            "entry" => {
                let e = ManifestEntry {
                    deposit_id: hex::decode(w[1]).unwrap().try_into().unwrap(),
                    amount: w[2].parse().unwrap(),
                    fees: FeeStructure::default(),
                    descriptor: w[3].to_string(),
                };
                let ours = owed_spk_sats(&e).map_or("residue".to_string(), |(spk, s)| {
                    format!("{}:{}", hex::encode(spk.as_bytes()), s)
                });
                assert_eq!(ours, w[5], "owed {}", w[1]);
                n += 1;
            }
            "tx" => {
                let pairs = |s: String| -> Vec<Vec<String>> {
                    if s.is_empty() {
                        Vec::new()
                    } else {
                        s.split(',')
                            .map(|p| p.split(':').map(String::from).collect())
                            .collect()
                    }
                };
                let swept = pairs(field("swept="))
                    .into_iter()
                    .map(|p| {
                        let mut o = txid(&p[0]);
                        o.vout = p[1].parse().unwrap();
                        (o, p[2].parse().unwrap())
                    })
                    .collect();
                let outs = pairs(field("outs="))
                    .into_iter()
                    .map(|p| {
                        (
                            bitcoin::ScriptBuf::from_hex(&p[0]).unwrap(),
                            p[1].parse().unwrap(),
                        )
                    })
                    .collect();
                let tx = build_confiscation_tx(&ConfiscationTxParams {
                    vault: (txid(&"a1".repeat(32)), 50_000_000),
                    swept,
                    lottery_spk: bitcoin::ScriptBuf::from_hex(&kv["lottery_spk"]).unwrap(),
                    voters: kv["voters"].parse().unwrap(),
                    lock_time: kv["locktime"].parse().unwrap(),
                    respectful: field("respectful=") == "1",
                    obligations_sats: field("obligations=").parse().unwrap(),
                    residue_sats: field("residue=").parse().unwrap(),
                    splice_outs: outs,
                    operator: kv["operator"].parse().unwrap(),
                    anchor: hex::decode(&kv["anchor"]).unwrap().try_into().unwrap(),
                });
                assert_eq!(
                    serialize_hex(&tx),
                    *w.last().unwrap(),
                    "confiscation {}",
                    w[1]
                );
                n += 1;
            }
            "record" => {
                let mut st = LedgerState::new(kv["operator"].parse().unwrap(), String::new(), 0);
                st.ledger_id = hex::decode(&kv["ledger"]).unwrap().try_into().unwrap();
                st.dispute_state = match w[2] {
                    "disputed" => DisputeState::Disputed,
                    "armed" => DisputeState::Armed,
                    _ => DisputeState::Normal,
                };
                let op = LedgerOperation::tlv_decode(&hex::decode(w[4]).unwrap()).unwrap();
                let got = if with_apply_ctx(at(160), || st.apply(&op)).is_ok() {
                    "ok"
                } else {
                    "refuse"
                };
                assert_eq!(got, w[3], "ObligationRecord {}", w[1]);
                n += 1;
            }
            "credit" => {
                let mut st = LedgerState::new(kv["operator"].parse().unwrap(), String::new(), 0);
                st.ledger_id = hex::decode(&kv["ledger"]).unwrap().try_into().unwrap();
                st.reserves_amount = kv["reserves"].parse().unwrap();
                let accept =
                    LedgerOperation::tlv_decode(&hex::decode(&kv["accept"]).unwrap()).unwrap();
                st = with_apply_ctx(at(100), || st.apply(&accept)).unwrap();
                st.confiscation_txid = Some(
                    hex::decode(&kv["confiscation_txid"])
                        .unwrap()
                        .try_into()
                        .unwrap(),
                );
                let credit = LedgerOperation::tlv_decode(&hex::decode(w[1]).unwrap()).unwrap();
                residue_state = Some(with_apply_ctx(at(300), || st.apply(&credit)).unwrap());
            }
            "balance" => {
                let id: [u8; 16] = hex::decode(w[1]).unwrap().try_into().unwrap();
                let bal = residue_state
                    .as_ref()
                    .unwrap()
                    .deposits
                    .get(&id)
                    .map_or(0, |d| d.balance);
                assert_eq!(bal.to_string(), w[2], "residue credit {}", w[1]);
                n += 1;
            }
            k => {
                kv.insert(k.to_string(), w[1].to_string());
            }
        }
    }
    assert_eq!(n, 16);
}

#[test]
fn unhonoured_obligation_matches_cl() {
    use deposits_core::fraud::verify_uncredited_onchain;
    let mut kv: HashMap<String, String> = HashMap::new();
    let mut history: Vec<SignedLedgerUpdate> = Vec::new();
    let mut n = 0;
    let mut hashes: HashMap<(String, String), String> = HashMap::new();
    let dec = |h: &str| SignedLedgerUpdate::tlv_decode(&hex::decode(h).unwrap()).unwrap();
    for line in include_str!("vectors/unhonoured_obligation.txt").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let w: Vec<&str> = line.split(' ').collect();
        let acquire = || {
            history
                .iter()
                .find(|u| {
                    matches!(
                        LedgerOperation::tlv_decode(&u.message),
                        Ok(LedgerOperation::DisputeAcquire { .. })
                    )
                })
                .unwrap()
                .clone()
        };
        let conf = || -> bitcoin::Transaction {
            bitcoin::consensus::deserialize(&hex::decode(&kv["confiscation"]).unwrap()).unwrap()
        };
        let oracle = |h: &[SignedLedgerUpdate], b: &[u8; 32]| {
            h.iter()
                .find(|u| &u.block_hash == b)
                .map(|u| u.block_height)
        };
        match w[0] {
            "update" => history.push(dec(w[1])),
            "payment" => {
                kv.insert("payment".into(), line[8..].to_string());
            }
            "offer" => {
                let json = &line[line.find(" json ").unwrap() + 6..];
                let p: FraudProof = serde_json::from_str(json).unwrap();
                assert_eq!(hex::encode(p.proof_hash()), w[5], "offer {} hash", w[1]);
                let pre: Vec<SignedLedgerUpdate> = history
                    .iter()
                    .filter(|u| u.sequence_number <= 5)
                    .cloned()
                    .collect();
                let o = |b: &[u8; 32]| oracle(&history, b);
                let v = verify_uncredited_onchain(&p, &pre, &o);
                assert_eq!(v.is_ok(), w[3] == "1", "offer {}: {v:?}", w[1]);
                n += 1;
            }
            "record" => {
                let pre: Vec<&SignedLedgerUpdate> =
                    history.iter().filter(|u| u.sequence_number <= 6).collect();
                let open = LedgerOperation::tlv_decode(&pre[0].message).unwrap();
                let LedgerOperation::LedgerOpen {
                    operator_id,
                    reserves_id,
                    genesis_block,
                    ..
                } = open
                else {
                    panic!("seq 0")
                };
                let mut st = LedgerState::new(operator_id, reserves_id, genesis_block);
                for u in &pre {
                    st.apply_update_in_place(u).unwrap();
                }
                let op = LedgerOperation::tlv_decode(&hex::decode(w[3]).unwrap()).unwrap();
                let got = if with_apply_ctx(at(172), || st.apply(&op)).is_ok() {
                    "ok"
                } else {
                    "refuse"
                };
                assert_eq!(got, w[2], "payment ObligationRecord {}", w[1]);
                n += 1;
            }
            "produce" => {
                let upto: u64 = w[2].parse().unwrap();
                let h: Vec<SignedLedgerUpdate> = history
                    .iter()
                    .filter(|u| u.sequence_number <= upto)
                    .cloned()
                    .collect();
                let (nu, qu) = (dec(&kv["notice"]), dec(&kv["qb"]));
                let p = if w[1] == "migration" {
                    unhonoured_obligation_proof(&h, &acquire(), &conf(), Some(&nu), Some(&qu), None)
                } else {
                    unhonoured_obligation_proof(
                        &h,
                        &acquire(),
                        &conf(),
                        None,
                        None,
                        Some(&kv["payment"]),
                    )
                };
                let got = p.map_or("none".to_string(), |p| match p.evidence {
                    FraudEvidence::UnhonouredObligation { proof_update, .. } => {
                        dec(&proof_update).sequence_number.to_string()
                    }
                    _ => "other".into(),
                });
                assert_eq!(got, w[3], "{line}");
                n += 1;
            }
            "proof" => {
                let mig = w[1] == "migration";
                let seq: u64 = w[2].parse().unwrap();
                let pu = history.iter().find(|u| u.sequence_number == seq).unwrap();
                let proof = FraudProof {
                    proof_type: FraudProofType::UnhonouredObligation,
                    accused: kv["accused"].clone(),
                    ledger_id: kv["ledger"].clone(),
                    evidence: FraudEvidence::UnhonouredObligation {
                        source_notice_update: if mig {
                            kv["notice"].clone()
                        } else {
                            String::new()
                        },
                        source_qb_update: if mig { kv["qb"].clone() } else { String::new() },
                        uncredited_proof: if mig {
                            String::new()
                        } else {
                            kv["payment"].clone()
                        },
                        acquire_update: hex::encode(acquire().tlv_encode()),
                        confiscation_tx: kv["confiscation"].clone(),
                        proof_update: hex::encode(pu.tlv_encode()),
                    },
                };
                assert_eq!(
                    hex::encode(proof.proof_hash()),
                    w[6],
                    "{} hash at {seq}",
                    w[1]
                );
                assert!(!proof.requires_embedding());
                let o = |b: &[u8; 32]| oracle(&history, b);
                let v = verify_unhonoured_obligation(&proof, &history, &o);
                assert_eq!(v.is_ok(), w[4] == "1", "{} verdict at {seq}: {v:?}", w[1]);
                hashes.insert((w[1].to_string(), w[2].to_string()), w[6].to_string());
                n += 1;
            }
            "json" => {
                // Proof 11 as cl broadcasts it: we must parse it as UnhonouredObligation (a
                // mis-tagged variant made us drop every one, regtest 2026-10-14), same hash.
                let json = &line[w[0].len() + w[1].len() + w[2].len() + 3..];
                let p: FraudProof = serde_json::from_str(json)
                    .unwrap_or_else(|e| panic!("cl's proof 11 ({}) does not parse: {e}", w[1]));
                assert!(
                    matches!(p.evidence, FraudEvidence::UnhonouredObligation { .. }),
                    "{}: evidence variant",
                    w[1]
                );
                assert_eq!(
                    hex::encode(p.proof_hash()),
                    hashes[&(w[1].to_string(), w[2].to_string())],
                    "{} json hash",
                    w[1]
                );
                n += 1;
            }
            k => {
                kv.insert(k.to_string(), w[1].to_string());
            }
        }
    }
    assert_eq!(n, 22);
}

/// A proof 11's history is the chain ending at its proof_update (DEP-06): rebuilt by
/// previous_hash from any pool of the ledger's updates, decoys and order notwithstanding.
#[test]
fn proof_11_history_is_the_chain_through_the_proof_update() {
    use deposits_core::fraud::chain_through;
    let history: Vec<SignedLedgerUpdate> = include_str!("vectors/unhonoured_obligation.txt")
        .lines()
        .filter_map(|l| l.strip_prefix("update "))
        .map(|h| SignedLedgerUpdate::tlv_decode(&hex::decode(h).unwrap()).unwrap())
        .collect();
    let tip = history.last().unwrap().clone();
    // Shuffled, with a decoy that claims a link it does not have.
    let mut pool: Vec<SignedLedgerUpdate> = history.iter().rev().cloned().collect();
    let mut decoy = history[3].clone();
    decoy.message.push(0);
    pool.push(decoy);
    let chain = chain_through(&pool, &tip).expect("the whole chain is in the pool");
    assert_eq!(chain.len(), history.len());
    assert!(chain
        .iter()
        .zip(&history)
        .all(|(a, b)| a.chain_hash() == b.chain_hash()));
    // A missing link: no chain (a verifier fails closed rather than judge a gap).
    let gappy: Vec<SignedLedgerUpdate> = pool
        .iter()
        .filter(|u| u.sequence_number != 4)
        .cloned()
        .collect();
    assert!(chain_through(&gappy, &tip).is_none());
}
