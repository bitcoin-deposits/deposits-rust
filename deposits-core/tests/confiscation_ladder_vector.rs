//! DEP-03 §Confiscation ladder, against the vector cl-deposits generates
//! (inspect/gen-confiscation-ladder.lisp): every rung of each case byte for byte, the decoys no
//! ladder contains, and the claim of a higher rung.

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
use deposits_core::tapscript_reserves::{
    build_confiscation_ladder, build_lottery_claim_tx, ConfiscationTxParams,
};
use serde_json::Value;

fn outpoint(v: &Value) -> (bitcoin::OutPoint, u64) {
    let txid: [u8; 32] = hex::decode(v["txid"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    (
        bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array(txid),
            vout: v["vout"].as_u64().unwrap() as u32,
        },
        v["sats"].as_u64().unwrap(),
    )
}

fn spk(v: &Value) -> bitcoin::ScriptBuf {
    bitcoin::ScriptBuf::from_hex(v.as_str().unwrap()).unwrap()
}

#[test]
fn confiscation_ladder_vector() {
    let v: Value = serde_json::from_str(include_str!("vectors/confiscation_ladder.json")).unwrap();
    let mut ladders = std::collections::HashMap::new();
    for c in v["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let p = &c["params"];
        let params = ConfiscationTxParams {
            vault: outpoint(&p["vault"]),
            swept: p["swept"]
                .as_array()
                .unwrap()
                .iter()
                .map(outpoint)
                .collect(),
            lottery_spk: spk(&p["lottery_spk"]),
            voters: p["voters"].as_u64().unwrap() as usize,
            lock_time: p["lock_time"].as_u64().unwrap() as u32,
            respectful: p["respectful"].as_bool().unwrap(),
            obligations_sats: p["obligations_sats"].as_u64().unwrap(),
            residue_sats: p["residue_sats"].as_u64().unwrap(),
            splice_outs: p["splice_outs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| (spk(&o["spk"]), o["sats"].as_u64().unwrap()))
                .collect(),
            operator: p["operator"].as_str().unwrap().parse().unwrap(),
            anchor: hex::decode(p["anchor"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            feerate_sat_vb: p["feerate"].as_u64().unwrap(),
        };
        let ladder = build_confiscation_ladder(&params, p["collateral_msats"].as_u64().unwrap());
        let want: Vec<&str> = c["rungs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap())
            .collect();
        assert_eq!(ladder.len(), want.len(), "{name}: rung count");
        let inputs = params.vault.1 + params.swept.iter().map(|(_, s)| *s).sum::<u64>();
        for (i, (r, w)) in ladder.iter().zip(&want).enumerate() {
            assert_eq!(serialize_hex(r), *w, "{name}: rung {i}");
            let out: u64 = r.output.iter().map(|o| o.value.to_sat()).sum();
            assert_eq!(
                inputs - out,
                c["fees"][i].as_u64().unwrap(),
                "{name}: rung {i} fee"
            );
        }
        ladders.insert(name.to_string(), ladder);
    }
    for d in v["decoys"].as_array().unwrap() {
        let ladder = &ladders[d["case"].as_str().unwrap()];
        let tx = d["tx"].as_str().unwrap();
        assert!(
            ladder.iter().all(|r| serialize_hex(r) != tx),
            "decoy accepted: {}",
            d["why"]
        );
    }
    let cl = &v["claim"];
    let rung = &ladders[cl["case"].as_str().unwrap()][cl["rung"].as_u64().unwrap() as usize];
    let (collateral, sats) = outpoint(&cl["collateral"]);
    let claim = build_lottery_claim_tx(
        bitcoin::OutPoint {
            txid: rung.compute_txid(),
            vout: 0,
        },
        rung.output[0].value.to_sat(),
        Some((collateral, sats)),
        spk(&cl["destination_spk"]),
        cl["fee"].as_u64().unwrap(),
        cl["subset"].as_bool().unwrap(),
    );
    assert_eq!(
        serialize_hex(&claim),
        cl["tx"].as_str().unwrap(),
        "the claim of a higher rung"
    );
}
