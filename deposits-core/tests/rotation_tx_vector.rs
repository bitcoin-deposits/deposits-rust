//! DEP-03 §"Rotation transaction": the unsigned rotation, byte for byte, pinned by the
//! vector shared with cl-deposits (inspect/vectors/rotation_tx.txt there). Each case
//! carries its own inputs, so the other implementation rebuilds from the file alone.
//! `REGEN_ROTATION_VECTOR=1 cargo test --test rotation_tx_vector` rewrites the file.

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{OutPoint, ScriptBuf, Txid};
use deposits_core::tapscript_reserves::{build_rotation_tx, RotationTxParams};
use std::str::FromStr;

fn outpoint(byte: u8, vout: u32) -> OutPoint {
    OutPoint::new(
        Txid::from_str(&format!("{:02x}", byte).repeat(32)).unwrap(),
        vout,
    )
}
fn p2tr(byte: u8) -> ScriptBuf {
    ScriptBuf::from_hex(&format!("5120{}", format!("{:02x}", byte).repeat(32))).unwrap()
}
fn p2wpkh(byte: u8) -> ScriptBuf {
    ScriptBuf::from_hex(&format!("0014{}", format!("{:02x}", byte).repeat(20))).unwrap()
}

fn cases() -> Vec<(&'static str, RotationTxParams)> {
    let base = RotationTxParams {
        vault: outpoint(0xa1, 0),
        vault_sats: 50_000_000,
        voters: 8,
        feerate_sat_vb: 2,
        lock_time: 0,
        new_vault_spk: p2tr(0xb2),
        splice_in: None,
        extra_outputs: vec![],
    };
    vec![
        ("plain", base.clone()),
        (
            "exits",
            RotationTxParams {
                extra_outputs: vec![(p2wpkh(0xc3), 1_000_000), (p2tr(0xc4), 250_000)],
                ..base.clone()
            },
        ),
        (
            "splice_in",
            RotationTxParams {
                splice_in: Some((outpoint(0xd5, 3), 7_500_000)),
                feerate_sat_vb: 5,
                ..base.clone()
            },
        ),
        (
            "migration_tier1",
            RotationTxParams {
                extra_outputs: vec![(p2wpkh(0xc3), 1_000_000), (p2tr(0xe6), 400_000)],
                lock_time: 12_345,
                voters: 6,
                ..base.clone()
            },
        ),
    ]
}

fn render() -> String {
    let mut out =
        String::from("# DEP-03 rotation transaction vector (shared cl-deposits / deposits-rust)\n");
    for (name, p) in cases() {
        out += &format!("case {name}\n");
        out += &format!("vault {}:{} {}\n", p.vault.txid, p.vault.vout, p.vault_sats);
        out += &format!(
            "voters {}\nfeerate {}\nlocktime {}\n",
            p.voters, p.feerate_sat_vb, p.lock_time
        );
        out += &format!("new_vault_spk {}\n", p.new_vault_spk.to_hex_string());
        if let Some((op, sats)) = p.splice_in {
            out += &format!("splice {}:{} {}\n", op.txid, op.vout, sats);
        }
        for (spk, sats) in &p.extra_outputs {
            out += &format!("out {} {}\n", spk.to_hex_string(), sats);
        }
        out += &format!("tx {}\n", serialize_hex(&build_rotation_tx(&p).unwrap()));
    }
    out
}

#[test]
fn rotation_tx_matches_shared_vector() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/rotation_tx.txt");
    let ours = render();
    if std::env::var("REGEN_ROTATION_VECTOR").is_ok() {
        std::fs::write(path, &ours).unwrap();
    }
    assert_eq!(std::fs::read_to_string(path).unwrap(), ours);
}

#[test]
fn rotation_below_dust_is_refused() {
    let mut p = cases().remove(0).1;
    p.vault_sats = 900;
    assert!(build_rotation_tx(&p).is_none());
}
