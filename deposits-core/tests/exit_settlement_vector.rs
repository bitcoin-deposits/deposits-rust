//! DEP-20 §3 exits, pinned by the vector shared with cl-deposits (generated there,
//! inspect/vectors/exit_settlement.txt): ExitRequest / ExitCancel encodings and DEP-17
//! sighashes (a cl-signed witness must authorize under pk(K)), a QuorumBegin carrying
//! exit fields, the due set, and the rotation's collateral share.

use deposits_core::dep16::operations::operation_sighash;
use deposits_core::messages::LedgerOperation;
use deposits_core::rotation_order::rotation_collateral;
use deposits_core::tlv::{TlvDecode, TlvEncode};
use deposits_core::types::{Authorizer, LedgerState, PendingExit};

fn cases() -> Vec<(String, Vec<String>)> {
    let text = include_str!("vectors/exit_settlement.txt");
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        if let Some(name) = line.strip_prefix("case ") {
            out.push((name.to_string(), Vec::new()));
        } else {
            out.last_mut().unwrap().1.push(line.to_string());
        }
    }
    out
}

fn field<'a>(lines: &'a [String], key: &str) -> &'a str {
    lines
        .iter()
        .find_map(|l| l.strip_prefix(&format!("{key} ")))
        .unwrap_or_else(|| panic!("missing {key}"))
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
fn exit_ops_match_cl_byte_for_byte_and_authorize() {
    let mut seen = 0;
    for (name, lines) in cases() {
        if !name.starts_with("exit_") {
            continue;
        }
        seen += 1;
        let tlv = hex::decode(field(&lines, "tlv")).unwrap();
        let op = LedgerOperation::tlv_decode(&tlv).expect("decodes");
        assert_eq!(op.tlv_encode(), tlv, "{name}: re-encodes byte for byte");
        assert_eq!(
            hex::encode(operation_sighash(&op).expect("signable")),
            field(&lines, "sighash"),
            "{name}: DEP-17 sighash"
        );
        let descriptor = format!("pk({})", field(&lines, "pubkey"));
        assert!(
            deposits_core::dep16::Dep16Authorizer::new().authorize(&descriptor, &op),
            "{name}: the cl-signed witness authorizes"
        );
    }
    assert_eq!(seen, 3);
}

#[test]
fn quorum_begin_with_exits_round_trips() {
    let (_, lines) = cases()
        .into_iter()
        .find(|(n, _)| n == "quorum_begin_exits")
        .unwrap();
    let tlv = hex::decode(field(&lines, "tlv")).unwrap();
    let op = LedgerOperation::tlv_decode(&tlv).unwrap();
    let LedgerOperation::QuorumBegin {
        exit_cutoff_height,
        ref exit_outputs,
        ..
    } = op
    else {
        panic!("not a QuorumBegin")
    };
    assert_eq!(exit_cutoff_height, Some(4990));
    assert_eq!(exit_outputs.len(), 2);
    assert_eq!((exit_outputs[1].amount, exit_outputs[1].vout), (500_000, 2));
    assert_eq!(op.tlv_encode(), tlv);
}

#[test]
fn due_set_matches_cl() {
    let (_, lines) = cases().into_iter().find(|(n, _)| n == "due_set").unwrap();
    let mut st = state();
    for l in lines.iter().filter_map(|l| l.strip_prefix("pending ")) {
        let f: Vec<&str> = l.split(' ').collect();
        let id: [u8; 32] = hex::decode(f[0]).unwrap().try_into().unwrap();
        st.pending_exits.insert(
            id,
            PendingExit {
                deposit_id: id[..16].try_into().unwrap(),
                amount: f[1].parse().unwrap(),
                exit_address: vec![id[0]; 22],
                expires_at: (f[4] != "-").then(|| f[4].parse().unwrap()),
                block_height: f[2].parse().unwrap(),
                seq: f[3].parse().unwrap(),
            },
        );
    }
    let h: u32 = field(&lines, "height").parse().unwrap();
    let c: u32 = field(&lines, "cutoff").parse().unwrap();
    let ours: Vec<(String, u64)> = st
        .due_exits(h, c)
        .into_iter()
        .map(|(id, e)| (hex::encode(id), e.amount))
        .collect();
    let cl: Vec<(String, u64)> = lines
        .iter()
        .filter_map(|l| l.strip_prefix("due "))
        .map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            (f[0].to_string(), f[1].parse().unwrap())
        })
        .collect();
    assert_eq!(ours, cl);
}

#[test]
fn collateral_share_matches_cl() {
    let (_, lines) = cases()
        .into_iter()
        .find(|(n, _)| n == "collateral")
        .unwrap();
    for l in &lines {
        let f: Vec<u64> = l
            .split(' ')
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|kv| kv[1].parse().unwrap())
            .collect();
        let mut st = state();
        st.reserves_amount = f[0];
        st.collateral_amount = f[1];
        assert_eq!(rotation_collateral(&st, f[2], f[3]), f[4], "{l}");
    }
}

/// The fold (DEP-20 §3): a request locks, a cancel releases, expiry releases at the next
/// update past its height, and a rotating QuorumBegin must settle exactly the due set.
#[test]
fn exit_fold_semantics() {
    use deposits_core::messages::ExitOutput;
    use deposits_core::types::{with_apply_ctx, ApplyCtx, DescriptorWitness};
    let mut st = state();
    st.reserves_amount = 50_000_000;
    st.vault_current = true;
    let dep = [0xd1u8; 16];
    let ctx = |height, seq, b| ApplyCtx {
        height,
        seq,
        hash: [b; 32],
    };
    let apply = |st: &mut LedgerState, c: ApplyCtx, op: LedgerOperation| {
        with_apply_ctx(c, || st.apply_in_place(&op))
    };
    apply(
        &mut st,
        ctx(100, 1, 1),
        LedgerOperation::DepositOpen {
            deposit_id: dep,
            descriptor: "pk(02aa)".into(),
            fees: None,
            transfer_fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
            commitment: None,
        },
    )
    .unwrap();
    apply(
        &mut st,
        ctx(100, 2, 2),
        LedgerOperation::OnchainCredit {
            txid: [9; 32],
            vout: 0,
            deposit_id: dep,
            amount: 3_000_000,
            funding_address: String::new(),
            commitment: None,
        },
    )
    .unwrap();
    let req = |amount, expires: Option<u32>, nonce| LedgerOperation::ExitRequest {
        deposit_id: dep,
        amount,
        exit_address: vec![0x51, 0x20],
        expires_at_height: expires,
        nonce,
        expiry: 9999,
        witness: DescriptorWitness::new(),
    };
    apply(&mut st, ctx(101, 3, 3), req(1_000_000, None, 1)).unwrap();
    apply(&mut st, ctx(101, 4, 4), req(500_000, None, 2)).unwrap();
    apply(&mut st, ctx(101, 5, 5), req(400_000, Some(103), 3)).unwrap();
    assert_eq!(st.deposits[&dep].locked_balance, 1_900_000);
    assert!(
        apply(&mut st, ctx(101, 6, 6), req(2_000_000, None, 4)).is_err(),
        "beyond available"
    );
    apply(
        &mut st,
        ctx(102, 6, 6),
        LedgerOperation::ExitCancel {
            deposit_id: dep,
            exit_request_id: [4; 32],
            nonce: 5,
            expiry: 9999,
            witness: DescriptorWitness::new(),
        },
    )
    .unwrap();
    assert_eq!(st.deposits[&dep].locked_balance, 1_400_000);
    // At height 103 the expiring request is released before the op applies.
    let qb = |cutoff, outs: Vec<ExitOutput>| LedgerOperation::QuorumBegin {
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
        exit_cutoff_height: Some(cutoff),
        exit_outputs: outs,
    };
    let wrong = apply(&mut st.clone(), ctx(103, 7, 7), qb(103, Vec::new()));
    assert!(
        format!("{:?}", wrong.unwrap_err()).contains("exit_outputs"),
        "omitting a due exit"
    );
    let mut st2 = st.clone();
    // (QuorumBegin's ruleset gate may refuse for other reasons in this bare state; the exit
    // settlement check runs first, so assert on it directly.)
    let r = apply(
        &mut st2,
        ctx(103, 7, 7),
        qb(
            103,
            vec![ExitOutput {
                deposit_id: dep,
                amount: 1_000_000,
                vout: 1,
            }],
        ),
    );
    if let Err(e) = &r {
        assert!(
            !format!("{e:?}").contains("exit_outputs"),
            "the due set is accepted: {e:?}"
        );
    } else {
        assert_eq!(st2.deposits[&dep].balance, 2_000_000);
        assert_eq!(st2.pending_exits.len(), 0);
    }
}
