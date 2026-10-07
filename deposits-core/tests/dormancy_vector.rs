//! DEP-20 §8 dormancy and DEP-03 reference feerate, pinned by the vector cl-deposits
//! generates (inspect/vectors/dormancy.txt there): pk() key-path addresses, the bucket's
//! spin-outs, the dormancy floor, and the feerate median and bounds.

use deposits_core::rotation_order::feerate_bounds;
use deposits_core::types::{pk_key_path_spk, Deposit, LedgerState, PendingExit};

fn cases() -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for line in include_str!("vectors/dormancy.txt")
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        if let Some(n) = line.strip_prefix("case ") {
            out.push((n.to_string(), Vec::new()));
        } else {
            out.last_mut().unwrap().1.push(line.to_string());
        }
    }
    out
}

fn state() -> LedgerState {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
    LedgerState::new(
        bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk),
        String::new(),
        0,
    )
}

#[test]
fn dormancy_vector_matches_cl() {
    let mut checked = 0;
    for (name, lines) in cases() {
        match name.as_str() {
            "pk_address" => {
                for l in &lines {
                    let w: Vec<&str> = l.split(' ').collect();
                    let ours = pk_key_path_spk(w[1])
                        .map_or("-".to_string(), |s| hex::encode(s.as_bytes()));
                    assert_eq!(ours, w[2], "{}", w[1]);
                    checked += 1;
                }
            }
            "bucket" => {
                let mut st = state();
                st.vault_current = true;
                let mut kv = std::collections::HashMap::new();
                let mut ats = Vec::new();
                for l in &lines {
                    let w: Vec<&str> = l.split(' ').collect();
                    match w[0] {
                        "deposit" => {
                            let id: [u8; 16] = hex::decode(w[1]).unwrap().try_into().unwrap();
                            let mut d = Deposit::new(w[2].to_string(), None);
                            d.deposit_id = id;
                            d.balance = w[3].parse().unwrap();
                            d.locked_balance = w[4].parse().unwrap();
                            d.last_signed_activity = w[5].parse().unwrap();
                            st.deposits.insert(id, d);
                        }
                        "pending_exit" => {
                            let id: [u8; 16] = hex::decode(w[1]).unwrap().try_into().unwrap();
                            st.pending_exits.insert(
                                [0xee; 32],
                                PendingExit {
                                    deposit_id: id,
                                    amount: 1000,
                                    exit_address: vec![0],
                                    expires_at: None,
                                    block_height: 0,
                                    seq: 0,
                                },
                            );
                        }
                        "at" => ats.push(w.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
                        k => {
                            kv.insert(k.to_string(), w[1].to_string());
                        }
                    }
                }
                st.reference_feerate = Some(kv["feerate"].parse().unwrap());
                st.dormancy_blocks = kv["dormancy_blocks"].parse().unwrap();
                st.dormancy_notice = Some((
                    kv["notice_height"].parse().unwrap(),
                    kv["rotation_height"].parse().unwrap(),
                ));
                assert_eq!(st.dormancy_amount_msats().to_string(), kv["floor_msat"]);
                for w in ats {
                    let ours: Vec<String> = st
                        .dormancy_spin_outs(w[1].parse().unwrap())
                        .into_iter()
                        .map(|(id, bal, spk)| {
                            format!(
                                "{}:{}:{}",
                                hex::encode(id),
                                bal,
                                hex::encode(spk.as_bytes())
                            )
                        })
                        .collect();
                    assert_eq!(ours, w[2..].to_vec(), "spin-outs at {}", w[1]);
                    checked += 1;
                }
            }
            "feerate" => {
                for l in &lines {
                    let w: Vec<&str> = l.split(' ').collect();
                    let mut fs: Vec<u64> = w[1..7].iter().map(|x| x.parse().unwrap()).collect();
                    fs.sort_unstable();
                    let m = (fs[2] + fs[3]) / 2;
                    let (lo, hi) = feerate_bounds(m);
                    assert_eq!(
                        (m, lo, hi),
                        (
                            w[8].parse().unwrap(),
                            w[10].parse().unwrap(),
                            w[12].parse().unwrap()
                        ),
                        "{l}"
                    );
                    checked += 1;
                }
            }
            _ => {}
        }
    }
    assert!(checked >= 9);
}

/// The fold: a notice, then the QuorumBegin consuming it must record exactly the spin-outs,
/// which it debits to zero; a notice too early, or a second one, is refused.
#[test]
fn dormancy_fold() {
    use deposits_core::messages::{ExitOutput, LedgerOperation};
    use deposits_core::types::{with_apply_ctx, ApplyCtx};
    let mut st = state();
    st.vault_current = true;
    st.dormancy_blocks = 5;
    st.dormancy_notice_blocks = 3;
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let k = bitcoin::secp256k1::PublicKey::from_secret_key(
        &secp,
        &bitcoin::secp256k1::SecretKey::from_slice(&[7; 32]).unwrap(),
    );
    let desc = format!("pk({})", hex::encode(k.serialize()));
    let mut d = Deposit::new(desc, None);
    d.balance = 3_000_000;
    let id = d.deposit_id;
    st.deposits.insert(id, d);
    st.rebuild_balance_cache();
    let at = |h| ApplyCtx {
        height: h,
        seq: 1,
        hash: [0; 32],
    };
    let notice = |r| LedgerOperation::DormancyNotice {
        rotation_height: r,
        migration_receiver: None,
        manifest_hash: None,
    };
    assert!(
        with_apply_ctx(at(10), || st.apply(&notice(12))).is_err(),
        "less than notice_blocks ahead"
    );
    st = with_apply_ctx(at(10), || st.apply(&notice(13))).unwrap();
    assert!(
        with_apply_ctx(at(10), || st.apply(&notice(20))).is_err(),
        "one outstanding"
    );
    let qb = |outs: Vec<ExitOutput>| LedgerOperation::QuorumBegin {
        reserves_id: "x".into(),
        spending_txid: [0; 32],
        new_outpoint_txid: [0; 32],
        new_outpoint_vout: 0,
        amount: 45_000_000,
        quorum_expiry: 9000,
        ledger_hash: [0; 32],
        quorum_members: Vec::new(),
        collateral_amount: 20_000_000,
        protocol_version: Some("cltv-offset-v2".into()),
        exit_cutoff_height: Some(14),
        exit_outputs: Vec::new(),
        splice_in_outpoint: None,
        splice_in_amount: None,
        reference_feerate: None,
        dormancy_outputs: outs,
    };
    let e = with_apply_ctx(at(14), || st.apply(&qb(Vec::new()))).unwrap_err();
    assert!(
        format!("{e:?}").contains("dormancy_outputs"),
        "omitting the spin-out: {e:?}"
    );
    let r = with_apply_ctx(at(14), || {
        st.apply(&qb(vec![ExitOutput {
            deposit_id: id,
            amount: 3_000_000,
            vout: 1,
        }]))
    });
    if let Err(e) = &r {
        assert!(
            !format!("{e:?}").contains("dormancy_outputs"),
            "the spin-out is accepted: {e:?}"
        );
    } else {
        let next = r.unwrap();
        assert_eq!(next.deposits[&id].balance, 0);
        assert!(next.dormancy_notice.is_none());
    }
}
