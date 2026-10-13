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
    let mut kv: HashMap<String, String> = HashMap::new();
    let mut history: Vec<SignedLedgerUpdate> = Vec::new();
    let mut n = 0;
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
        match w[0] {
            "update" => history.push(dec(w[1])),
            "produce" => {
                let upto: u64 = w[1].parse().unwrap();
                let h: Vec<SignedLedgerUpdate> = history
                    .iter()
                    .filter(|u| u.sequence_number <= upto)
                    .cloned()
                    .collect();
                let p = unhonoured_obligation_proof(
                    &h,
                    &acquire(),
                    &conf(),
                    &dec(&kv["notice"]),
                    &dec(&kv["qb"]),
                );
                let got = p.map_or("none".to_string(), |p| match p.evidence {
                    FraudEvidence::UnhonouredObligation { proof_update, .. } => {
                        dec(&proof_update).sequence_number.to_string()
                    }
                    _ => "other".into(),
                });
                assert_eq!(got, w[2], "{line}");
                n += 1;
            }
            "proof" => {
                let seq: u64 = w[1].parse().unwrap();
                let pu = history.iter().find(|u| u.sequence_number == seq).unwrap();
                let proof = FraudProof {
                    proof_type: FraudProofType::UnhonouredObligation,
                    accused: kv["accused"].clone(),
                    ledger_id: kv["ledger"].clone(),
                    evidence: FraudEvidence::UnhonouredObligation {
                        source_notice_update: kv["notice"].clone(),
                        source_qb_update: kv["qb"].clone(),
                        acquire_update: hex::encode(acquire().tlv_encode()),
                        confiscation_tx: kv["confiscation"].clone(),
                        proof_update: hex::encode(pu.tlv_encode()),
                    },
                };
                assert_eq!(hex::encode(proof.proof_hash()), w[5], "hash at {seq}");
                assert!(!proof.requires_embedding());
                let oracle = |b: &[u8; 32]| {
                    history
                        .iter()
                        .find(|u| &u.block_hash == b)
                        .map(|u| u.block_height)
                };
                let v = verify_unhonoured_obligation(&proof, &history, &oracle);
                assert_eq!(v.is_ok(), w[3] == "1", "verdict at {seq}: {v:?}");
                n += 1;
            }
            k => {
                kv.insert(k.to_string(), w[1].to_string());
            }
        }
    }
    assert_eq!(n, 6);
}
