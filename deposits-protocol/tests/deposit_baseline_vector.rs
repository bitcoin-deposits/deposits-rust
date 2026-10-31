//! DEP-07 deposit baselines, pinned by the vector shared with cl-deposits
//! (`tests/vectors/deposit_baseline.txt`). The open block and fee baseline are
//! set by the DepositOpen transition itself, so a replica applying the update
//! (not only the operator committing it) gets them (signet soak, 2026-10-31:
//! replicas left both at 0 and judged fees due 300 blocks early).

use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::types::{with_apply_ctx, ApplyCtx, LedgerState};

fn pk() -> bitcoin::secp256k1::PublicKey {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
    bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
}

#[test]
fn deposit_baselines_match_the_shared_vector() {
    let text = include_str!("vectors/deposit_baseline.txt");
    let mut n = 0;
    for line in text.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let v: Vec<u32> = line.split(' ').map(|x| x.parse().unwrap()).collect();
        let mut state = LedgerState::new(pk(), "r".to_string(), v[0]);
        let did = [3u8; 16];
        let ctx = ApplyCtx {
            height: v[1],
            seq: 1,
            hash: [0u8; 32],
        };
        with_apply_ctx(ctx, || {
            state.apply_in_place(&LedgerOperation::DepositOpen {
                deposit_id: did,
                descriptor:
                    "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
                        .to_string(),
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
            })
        })
        .unwrap();
        let d = state.deposits.get(&did).unwrap();
        assert_eq!(d.opened_at_block, v[2], "opened_at_block: {}", line);
        assert_eq!(d.last_fee_assessment, v[3], "last_fee_assessment: {}", line);
        let first = d.last_fee_assessment + 2016;
        assert_eq!(first, v[4], "first FeeCollect: {}", line);
        n += 1;
    }
    assert_eq!(n, 5);
}
